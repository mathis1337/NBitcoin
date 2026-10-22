using NBitcoin.DataEncoders;
using System.IO;
using System.Linq;
using Xunit;

namespace NBitcoin.Tests
{
	/// <summary>The VerifiedX signet network and the BIP 325 block solution check, against real blocks of both signets.</summary>
	public class vfx_signet_tests
	{
		// Real blocks: the VerifiedX signet's first retarget block (coinbase only) and a block with payments in it,
		// and a block of the public signet with 179 transactions.
		const string VfxBlockAtRetarget = "data/vfx-signet-block-2016.txt";
		const string VfxBlockWithPayments = "data/vfx-signet-block-2046.txt";
		const string PublicSignetBlock = "data/signet-block-327500.txt";

		static Block Load(string path, Network network) => Block.Parse(File.ReadAllText(path).Trim(), network);

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheVfxSignetIsItsOwnBitcoinNetwork()
		{
			var network = Network.VfxSignet;
			Assert.Same(network, Network.GetNetwork("vfx-signet"));
			Assert.Same(network, Network.GetNetwork("btc-vfx-signet"));
			Assert.Same(network, Bitcoin.Instance.VfxSignet);
			Assert.Same(network, Bitcoin.Instance.GetNetwork(network.ChainName));
			Assert.Same(Bitcoin.Instance, network.NetworkSet);
			Assert.NotSame(Network.GetNetwork("signet"), network);
			Assert.NotEqual(Network.GetNetwork("signet")!.ChainName, network.ChainName);

			Assert.Equal("c69e715c", Encoders.Hex.EncodeData(network.MagicBytes));
			Assert.Equal(38333, network.DefaultPort);
			Assert.Equal(Network.GetNetwork("signet")!.GenesisHash, network.GenesisHash);
			Assert.Equal(new Target(0x1e0377ae), network.Consensus.PowLimit);
			Assert.Empty(network.SeedNodes);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ThePublicSignetIsUnchanged()
		{
			var signet = Network.GetNetwork("signet")!;
			Assert.Equal("0a03cf40", Encoders.Hex.EncodeData(signet.MagicBytes));
			Assert.Equal(Bitcoin.PublicSignetChallenge, signet.Consensus.SignetChallenge);
			Assert.Equal(2, signet.SeedNodes.Count());
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void OnlySignetsCarryAChallenge()
		{
			Assert.Equal(Bitcoin.VfxSignetChallenge, Network.VfxSignet.Consensus.SignetChallenge);
			Assert.Null(Network.Main.Consensus.SignetChallenge);
			Assert.Null(Network.TestNet.Consensus.SignetChallenge);
			Assert.Null(Network.TestNet4.Consensus.SignetChallenge);
			Assert.Null(Network.RegTest.Consensus.SignetChallenge);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void AddressesAreTestnetAddresses()
		{
			var key = new Key();
			foreach (var type in new[] { ScriptPubKeyType.Legacy, ScriptPubKeyType.Segwit, ScriptPubKeyType.TaprootBIP86 })
			{
				var onSignet = key.PubKey.GetAddress(type, Network.VfxSignet).ToString();
				Assert.Equal(key.PubKey.GetAddress(type, Network.TestNet4).ToString(), onSignet);
				Assert.Equal(key.PubKey.GetAddress(type, Network.VfxSignet).ScriptPubKey,
					BitcoinAddress.Create(onSignet, Network.VfxSignet).ScriptPubKey);
			}
			Assert.StartsWith("tb1q", key.PubKey.GetAddress(ScriptPubKeyType.Segwit, Network.VfxSignet).ToString());
		}

		[Theory]
		[Trait("UnitTest", "UnitTest")]
		[InlineData(VfxBlockAtRetarget)]
		[InlineData(VfxBlockWithPayments)]
		public void RealVfxSignetBlocksAreSigned(string path)
		{
			var block = Load(path, Network.VfxSignet);
			Assert.True(SignetSolution.Verify(block, Network.VfxSignet, out var error), error);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void AVfxSignetBlockIsNotSignedForThePublicSignet()
		{
			var block = Load(VfxBlockWithPayments, Network.VfxSignet);
			Assert.False(SignetSolution.Verify(block, Bitcoin.PublicSignetChallenge, out var error));
			Assert.Contains("does not satisfy", error);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ARealPublicSignetBlockIsSigned()
		{
			var signet = Network.GetNetwork("signet")!;
			var block = Load(PublicSignetBlock, signet);
			Assert.Equal(179, block.Transactions.Count);
			Assert.True(SignetSolution.Verify(block, signet, out var error), error);
			Assert.False(SignetSolution.Verify(block, Network.VfxSignet, out _));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ABlockWithoutWitnessDataStillVerifies()
		{
			// The solution sits in a coinbase output, not in witness data, so a block fetched without witnesses is checked the same.
			var block = Load(VfxBlockWithPayments, Network.VfxSignet).WithOptions(TransactionOptions.None);
			Assert.True(SignetSolution.Verify(block, Network.VfxSignet, out var error), error);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ABlockWithATransactionTakenOutFails()
		{
			// The signature covers the block's transactions: the same coinbase over a different set no longer verifies.
			var block = Load(VfxBlockWithPayments, Network.VfxSignet);
			Assert.True(block.Transactions.Count > 1);
			block.Transactions.RemoveAt(block.Transactions.Count - 1);
			block.UpdateMerkleRoot();
			Assert.False(SignetSolution.Verify(block, Network.VfxSignet, out var error));
			Assert.Contains("does not satisfy", error);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ABlockWithADifferentTimeFails()
		{
			var block = Load(VfxBlockAtRetarget, Network.VfxSignet);
			block.Header.BlockTime = block.Header.BlockTime.AddSeconds(1);
			Assert.False(SignetSolution.Verify(block, Network.VfxSignet, out _));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ABlockWithATamperedSolutionFails()
		{
			var block = Load(VfxBlockAtRetarget, Network.VfxSignet);
			var coinbase = block.Transactions[0];
			var output = coinbase.Outputs.Last(o => o.ScriptPubKey.ToHex().StartsWith("6a24aa21a9ed"));
			var bytes = output.ScriptPubKey.ToBytes();
			bytes[bytes.Length - 10] ^= 0x01; // inside the signature
			output.ScriptPubKey = new Script(bytes);
			block.UpdateMerkleRoot();
			Assert.False(SignetSolution.Verify(block, Network.VfxSignet, out _));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ABlockWithoutAWitnessCommitmentFails()
		{
			var block = Load(VfxBlockAtRetarget, Network.VfxSignet);
			var coinbase = block.Transactions[0];
			var commitment = coinbase.Outputs.Last(o => o.ScriptPubKey.ToHex().StartsWith("6a24aa21a9ed"));
			coinbase.Outputs.Remove(commitment);
			block.UpdateMerkleRoot();
			Assert.False(SignetSolution.Verify(block, Network.VfxSignet, out var error));
			Assert.Equal("the coinbase has no witness commitment", error);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheGenesisBlockNeedsNoSolution()
		{
			Assert.True(SignetSolution.Verify(Network.VfxSignet.GetGenesis(), Network.VfxSignet, out var error), error);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ANetworkThatIsNotASignetIsRefused()
		{
			var block = Load(VfxBlockAtRetarget, Network.VfxSignet);
			Assert.False(SignetSolution.Verify(block, Network.TestNet4, out var error));
			Assert.Contains("is not a signet", error);
		}
	}
}
