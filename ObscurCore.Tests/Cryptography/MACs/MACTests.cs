using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Stream;

namespace ObscurCore.Tests.Cryptography.MACs
{
    class MACTests : MACTestBase
    {
        public MACTests() {
            SetRandomFixtureParameters(256);
        }

        [Test]
        public void BLAKE2B256 () {
			RunMACTest(MacFunction.Blake2B256, null, null, null, CreateRandomBytes(128));
        }

        [Test]
        public void BLAKE2B384 () {
			RunMACTest(MacFunction.Blake2B384, null, null, CreateRandomBytes(384), CreateRandomBytes(128));
        }

        [Test]
        public void BLAKE2B512 () {
			RunMACTest(MacFunction.Blake2B512, null, null, CreateRandomBytes(512), CreateRandomBytes(128));
        }

        [Test]
        public void Keccak224 () {
			RunMACTest(MacFunction.Keccak224, null, null, CreateRandomBytes(224), CreateRandomBytes(128));
        }

        [Test]
        public void Keccak256 () {
            RunMACTest(MacFunction.Keccak256);
        }

        [Test]
        public void Keccak384 () {
			RunMACTest(MacFunction.Keccak384, null, null, CreateRandomBytes(384));
        }

        [Test]
        public void Keccak512 () {
			RunMACTest(MacFunction.Keccak512, null, null, CreateRandomBytes(512));
        }

		[Test]
		public void Poly1305_AES () {
			RunMACTest(MacFunction.Poly1305, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Aes.ToString()), CreateRandomBytes(128));
		}
    }
}
