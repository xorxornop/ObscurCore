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
    class HMACTests : MACTestBase
    {
        const MacFunction function = MacFunction.Hmac;

        public HMACTests() {
            SetRandomFixtureParameters(128);
        }

        [Test]
        public void BLAKE2B256 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Blake2B256.ToString()));
        }

        [Test]
        public void BLAKE2B384 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Blake2B384.ToString()));
        }

        [Test]
        public void BLAKE2B512 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Blake2B512.ToString()));
        }

        [Test]
        public void Keccak224 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak224.ToString()));
        }

        [Test]
        public void Keccak256 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak256.ToString()));
        }

        [Test]
        public void Keccak384 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak384.ToString()));
        }

        [Test]
        public void Keccak512 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Keccak512.ToString()));
        }

        [Test]
        public void RIPEMD160 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Ripemd160.ToString()));
        }
#if INCLUDE_SHA1
        [Test]
        public void SHA1 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Sha1.ToString()));
        }
#endif
        [Test]
        public void SHA256 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Sha256.ToString()));
        }

        [Test]
        public void SHA512 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Sha512.ToString()));
        }

        [Test]
        public void Tiger () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Tiger.ToString()));
        }

        [Test]
        public void Whirlpool () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunction.Whirlpool.ToString()));
        }
    }
}
