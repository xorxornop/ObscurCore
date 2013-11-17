using NUnit.Framework;
using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.Digests
{
    class DigestTests : DigestTestBase
    {
        [Test]
        public void BLAKE2B256 () {
            RunDigestTest(HashFunctions.BLAKE2B256);
        }

        [Test]
        public void BLAKE2B384 () {
            RunDigestTest(HashFunctions.BLAKE2B384);
        }

        [Test]
        public void BLAKE2B512 () {
            RunDigestTest(HashFunctions.BLAKE2B512);
        }

        [Test]
        public void Keccak224 () {
            RunDigestTest(HashFunctions.Keccak224);
        }

        [Test]
        public void Keccak256 () {
            RunDigestTest(HashFunctions.Keccak256);
        }

        [Test]
        public void Keccak384 () {
            RunDigestTest(HashFunctions.Keccak384);
        }

        [Test]
        public void Keccak512 () {
            RunDigestTest(HashFunctions.Keccak512);
        }

        [Test]
        public void RIPEMD160 () {
            RunDigestTest(HashFunctions.RIPEMD160);
        }
#if INCLUDE_SHA1
        [Test]
        public void SHA1 () {
            RunDigestTest(HashFunctions.SHA1);
        }
#endif
        [Test]
        public void SHA256 () {
            RunDigestTest(HashFunctions.SHA256);
        }

        [Test]
        public void SHA512 () {
            RunDigestTest(HashFunctions.SHA512);
        }

        [Test]
        public void Tiger () {
            RunDigestTest(HashFunctions.Tiger);
        }

        [Test]
        public void Whirlpool () {
            RunDigestTest(HashFunctions.Whirlpool);
        }
    }
}
