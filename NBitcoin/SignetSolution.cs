#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NBitcoin
{
	/// <summary>
	/// BIP 325: the check that a block of a signet is signed by its challenge. A signet's proof of work is trivial, so
	/// this signature is what makes a block one of the chain's. Ported from Bitcoin Core's src/signet.cpp
	/// (CheckSignetBlockSolution and SignetTxs::Create).
	/// </summary>
	public static class SignetSolution
	{
		/// <summary>The four bytes that open the signet solution inside the coinbase's witness commitment output.</summary>
		static readonly byte[] SignetHeader = { 0xec, 0xc7, 0xda, 0xa2 };

		/// <summary>The script flags Bitcoin Core verifies a block solution with (BLOCK_SCRIPT_VERIFY_FLAGS).</summary>
		const ScriptVerify BlockScriptVerifyFlags = ScriptVerify.P2SH | ScriptVerify.Witness | ScriptVerify.DerSig | ScriptVerify.NullDummy;

		/// <summary>
		/// Whether <paramref name="block"/> carries a solution to <paramref name="network"/>'s signet challenge. The
		/// genesis block needs none. False with a reason otherwise; a network that is not a signet is refused.
		/// </summary>
		public static bool Verify(Block block, Network network, out string? error)
		{
			if (block == null)
				throw new ArgumentNullException(nameof(block));
			if (network == null)
				throw new ArgumentNullException(nameof(network));
			var challenge = network.Consensus.SignetChallenge;
			if (challenge == null)
			{
				error = $"{network.Name} is not a signet";
				return false;
			}
			if (block.GetHash() == network.GenesisHash)
			{
				error = null;
				return true;
			}
			return Verify(block, challenge, out error);
		}

		/// <summary>Whether <paramref name="block"/> carries a solution to <paramref name="challenge"/>. False with a reason otherwise.</summary>
		public static bool Verify(Block block, Script challenge, out string? error)
		{
			if (block == null)
				throw new ArgumentNullException(nameof(block));
			if (challenge == null)
				throw new ArgumentNullException(nameof(challenge));
			if (block.Transactions.Count == 0)
			{
				error = "the block has no coinbase transaction";
				return false;
			}

			var modifiedCoinbase = block.Transactions[0].Clone();
			var commitmentIndex = WitnessCommitmentIndex(modifiedCoinbase);
			if (commitmentIndex < 0)
			{
				error = "the coinbase has no witness commitment";
				return false;
			}

			var toSign = new Transaction { Version = 0, LockTime = LockTime.Zero };
			toSign.Inputs.Add(new TxIn(new OutPoint(), Script.Empty) { Sequence = 0 });
			toSign.Outputs.Add(new TxOut(Money.Zero, new Script(OpcodeType.OP_RETURN)));

			var commitment = modifiedCoinbase.Outputs[commitmentIndex].ScriptPubKey.ToBytes();
			if (!TryFetchAndClearCommitmentSection(commitment, out var cleared, out var solution))
			{
				error = "the witness commitment cannot be parsed";
				return false;
			}
			if (solution != null)
			{
				modifiedCoinbase.Outputs[commitmentIndex].ScriptPubKey = new Script(cleared);
				if (!TryReadSolution(solution, out var scriptSig, out var witness))
				{
					error = "the signet solution cannot be parsed";
					return false;
				}
				toSign.Inputs[0].ScriptSig = scriptSig;
				toSign.Inputs[0].WitScript = witness;
			}
			// No solution at all is allowed by Bitcoin Core (it supports OP_TRUE as a trivial challenge); the script
			// check below then decides.

			var leaves = new List<uint256>(block.Transactions.Count) { modifiedCoinbase.GetHash() };
			leaves.AddRange(block.Transactions.Skip(1).Select(tx => tx.GetHash()));
			var signetMerkle = MerkleNode.GetRoot(leaves).Hash;

			var blockData = new MemoryStream();
			var stream = new BitcoinStream(blockData, true);
			var version = block.Header.Version;
			stream.ReadWrite(ref version);
			var prev = block.Header.HashPrevBlock;
			stream.ReadWrite(ref prev);
			stream.ReadWrite(ref signetMerkle);
			var time = (uint)block.Header.BlockTime.ToUnixTimeSeconds();
			stream.ReadWrite(ref time);

			var toSpend = new Transaction { Version = 0, LockTime = LockTime.Zero };
			// OP_0 then the block data, pushed as CScript(OP_0) << block_data writes it.
			var spendScriptSig = new MemoryStream();
			spendScriptSig.WriteByte((byte)OpcodeType.OP_0);
			WritePush(spendScriptSig, blockData.ToArray());
			toSpend.Inputs.Add(new TxIn(new OutPoint(), new Script(spendScriptSig.ToArray())) { Sequence = 0 });
			toSpend.Outputs.Add(new TxOut(Money.Zero, challenge));
			toSign.Inputs[0].PrevOut = new OutPoint(toSpend.GetHash(), 0);

			var context = new ScriptEvaluationContext { ScriptVerify = BlockScriptVerifyFlags };
			var checker = new TransactionChecker(toSign, 0, toSpend.Outputs[0]);
			if (!context.VerifyScript(toSign.Inputs[0].ScriptSig, toSign.Inputs[0].WitScript, challenge, checker))
			{
				error = $"the block's signet solution does not satisfy the challenge ({context.Error})";
				return false;
			}
			error = null;
			return true;
		}

		/// <summary>The index of the coinbase output holding the witness commitment (the last one that does), or -1 (GetWitnessCommitmentIndex).</summary>
		static int WitnessCommitmentIndex(Transaction coinbase)
		{
			var index = -1;
			for (var i = 0; i < coinbase.Outputs.Count; i++)
			{
				var script = coinbase.Outputs[i].ScriptPubKey.ToBytes(true);
				if (script.Length >= 38 && script[0] == (byte)OpcodeType.OP_RETURN && script[1] == 0x24
					&& script[2] == 0xaa && script[3] == 0x21 && script[4] == 0xa9 && script[5] == 0xed)
					index = i;
			}
			return index;
		}

		/// <summary>
		/// Splits the witness commitment script as Bitcoin Core's FetchAndClearCommitmentSection does: the first push
		/// that starts with the signet header and carries more yields the solution, and the script is rebuilt with that
		/// push cut back to the header alone. <paramref name="solution"/> is null when there is no such push. False
		/// when the script cannot be read.
		/// </summary>
		static bool TryFetchAndClearCommitmentSection(byte[] script, out byte[] cleared, out byte[]? solution)
		{
			solution = null;
			var replacement = new MemoryStream();
			var pc = 0;
			while (pc < script.Length)
			{
				var opcode = script[pc++];
				byte[]? push = null;
				if (opcode <= (byte)OpcodeType.OP_PUSHDATA4)
				{
					long size;
					if (opcode < (byte)OpcodeType.OP_PUSHDATA1)
						size = opcode;
					else if (opcode == (byte)OpcodeType.OP_PUSHDATA1)
					{
						if (pc + 1 > script.Length) break;
						size = script[pc];
						pc += 1;
					}
					else if (opcode == (byte)OpcodeType.OP_PUSHDATA2)
					{
						if (pc + 2 > script.Length) break;
						size = script[pc] | (script[pc + 1] << 8);
						pc += 2;
					}
					else
					{
						if (pc + 4 > script.Length) break;
						size = (uint)(script[pc] | (script[pc + 1] << 8) | (script[pc + 2] << 16) | (script[pc + 3] << 24));
						pc += 4;
					}
					if (size > script.Length - pc) break;
					push = new byte[size];
					Array.Copy(script, pc, push, 0, size);
					pc += (int)size;
				}

				if (push != null && push.Length > 0)
				{
					if (solution == null && push.Length > SignetHeader.Length && push.Take(SignetHeader.Length).SequenceEqual(SignetHeader))
					{
						solution = push.Skip(SignetHeader.Length).ToArray();
						push = SignetHeader.ToArray();
					}
					WritePush(replacement, push);
				}
				else
				{
					replacement.WriteByte(opcode);
				}
			}
			// Bitcoin Core's GetOp stops at a push that runs past the end; such a commitment is refused here.
			cleared = replacement.ToArray();
			return pc >= script.Length;
		}

		/// <summary>A push as Bitcoin Core's CScript::operator&lt;&lt;(std::vector) writes it: the shortest length prefix, never a small-number opcode.</summary>
		static void WritePush(Stream output, byte[] data)
		{
			if (data.Length < (int)OpcodeType.OP_PUSHDATA1)
				output.WriteByte((byte)data.Length);
			else if (data.Length <= 0xff)
			{
				output.WriteByte((byte)OpcodeType.OP_PUSHDATA1);
				output.WriteByte((byte)data.Length);
			}
			else if (data.Length <= 0xffff)
			{
				output.WriteByte((byte)OpcodeType.OP_PUSHDATA2);
				output.WriteByte((byte)(data.Length & 0xff));
				output.WriteByte((byte)(data.Length >> 8));
			}
			else
			{
				output.WriteByte((byte)OpcodeType.OP_PUSHDATA4);
				output.Write(BitConverter.GetBytes((uint)data.Length), 0, 4);
			}
			output.Write(data, 0, data.Length);
		}

		/// <summary>The solution is a scriptSig then a witness stack, serialized, with nothing after them.</summary>
		static bool TryReadSolution(byte[] solution, out Script scriptSig, out WitScript witness)
		{
			scriptSig = Script.Empty;
			witness = WitScript.Empty;
			try
			{
				var ms = new MemoryStream(solution);
				var stream = new BitcoinStream(ms, false);
				byte[] sigBytes = new byte[0];
				stream.ReadWriteAsVarString(ref sigBytes);
				ulong count = 0;
				stream.ReadWriteAsVarInt(ref count);
				if (count > (ulong)solution.Length)
					return false;
				var items = new List<byte[]>();
				for (ulong i = 0; i < count; i++)
				{
					byte[] item = new byte[0];
					stream.ReadWriteAsVarString(ref item);
					items.Add(item);
				}
				if (ms.Position != ms.Length)
					return false;
				scriptSig = new Script(sigBytes);
				witness = new WitScript(items.ToArray());
				return true;
			}
			catch (Exception)
			{
				return false;
			}
		}
	}
}
