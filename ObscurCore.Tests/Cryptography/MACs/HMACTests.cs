using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;

namespace ObscurCore.Tests.Cryptography.MACs
{
    class HMACTests : MacTestBase
    {
        const MacFunction function = MacFunction.Hmac;

        public HMACTests() {
            SetRandomFixtureParameters(128);
        }

        [Test]
        public void BLAKE2B256 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Blake2B256.ToString()));
        }

        [Test]
        public void BLAKE2B384 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Blake2B384.ToString()));
        }

        [Test]
        public void BLAKE2B512 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Blake2B512.ToString()));
        }

        [Test]
        public void Keccak224 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak224.ToString()));
        }

        [Test]
        public void Keccak256 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak256.ToString()));
        }

        [Test]
        public void Keccak384 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak384.ToString()));
        }

        [Test]
        public void Keccak512 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak512.ToString()));
        }

        [Test]
        public void RIPEMD160 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Ripemd160.ToString()));
        }
#if INCLUDE_SHA1
        [Test]
        public void SHA1 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Sha1.ToString()));
        }
#endif
        [Test]
        public void SHA256 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Sha256.ToString()));
        }

        [Test]
        public void SHA512 () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Sha512.ToString()));
        }

        [Test]
        public void Tiger () {
            RunMacTest(function, Encoding.UTF8.GetBytes(HashFunction.Tiger.ToString()));
        }
    }
}
