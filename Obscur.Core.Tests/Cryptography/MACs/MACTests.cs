using System.Text;
using NUnit.Framework;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.MACs
{
    class MACTests : MacTestBase
    {
        public MACTests() {
            SetRandomFixtureParameters(256);
        }

        [Test]
        public void BLAKE2B256 () {
			RunMacTest(MacFunction.Blake2B256, null, null, null, CreateRandomBytes(128));
        }

        [Test]
        public void BLAKE2B384 () {
			RunMacTest(MacFunction.Blake2B384, null, null, CreateRandomBytes(384), CreateRandomBytes(128));
        }

        [Test]
        public void BLAKE2B512 () {
			RunMacTest(MacFunction.Blake2B512, null, null, CreateRandomBytes(512), CreateRandomBytes(128));
        }

//        [Test]
//        public void Keccak224 () {
//			RunMacTest(MacFunction.Keccak224, null, null, CreateRandomBytes(224), CreateRandomBytes(128));
//        }

        [Test]
        public void Keccak256 () {
            RunMacTest(MacFunction.Keccak256);
        }

        [Test]
        public void Keccak384 () {
			RunMacTest(MacFunction.Keccak384, null, null, CreateRandomBytes(384));
        }

        [Test]
        public void Keccak512 () {
			RunMacTest(MacFunction.Keccak512, null, null, CreateRandomBytes(512));
        }

		[Test]
		public void Poly1305_AES () {
			RunMacTest(MacFunction.Poly1305, Encoding.UTF8.GetBytes(BlockCipher.Aes.ToString()), CreateRandomBytes(128));
		}
    }
}
