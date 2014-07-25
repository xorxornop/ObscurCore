using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;

namespace ObscurCore.Tests.Cryptography.Digests
{
    class DigestTests : DigestTestBase
    {
        [Test]
        public void BLAKE2B256 () {
            RunDigestTest(HashFunction.Blake2B256);
        }

        [Test]
        public void BLAKE2B384 () {
            RunDigestTest(HashFunction.Blake2B384);
        }

        [Test]
        public void BLAKE2B512 () {
            RunDigestTest(HashFunction.Blake2B512);
        }

        [Test]
        public void Keccak224 () {
            RunDigestTest(HashFunction.Keccak224);
        }

        [Test]
        public void Keccak256 () {
            RunDigestTest(HashFunction.Keccak256);
        }

        [Test]
        public void Keccak384 () {
            RunDigestTest(HashFunction.Keccak384);
        }

        [Test]
        public void Keccak512 () {
            RunDigestTest(HashFunction.Keccak512);
        }

        [Test]
        public void RIPEMD160 () {
            RunDigestTest(HashFunction.Ripemd160);
        }
#if INCLUDE_SHA1
        [Test]
        public void SHA1 () {
            RunDigestTest(HashFunction.Sha1);
        }
#endif
        [Test]
        public void SHA256 () {
            RunDigestTest(HashFunction.Sha256);
        }

        [Test]
        public void SHA512 () {
            RunDigestTest(HashFunction.Sha512);
        }

        [Test]
        public void Tiger () {
            RunDigestTest(HashFunction.Tiger);
        }

        [Test]
        public void Whirlpool()
        {
            RunDigestTest(HashFunction.Whirlpool);
        }
    }
}
