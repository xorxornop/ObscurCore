using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.MACs
{
    class HMACTests : MACTestBase
    {
        const MACFunctions function = MACFunctions.HMAC;

        public HMACTests() {
            SetRandomFixtureParameters(128);
        }

        [Test]
        public void BLAKE2B256 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.BLAKE2B256.ToString()));
        }

        [Test]
        public void BLAKE2B384 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.BLAKE2B384.ToString()));
        }

        [Test]
        public void BLAKE2B512 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.BLAKE2B512.ToString()));
        }

        [Test]
        public void Keccak224 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.Keccak224.ToString()));
        }

        [Test]
        public void Keccak256 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.Keccak256.ToString()));
        }

        [Test]
        public void Keccak384 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.Keccak384.ToString()));
        }

        [Test]
        public void Keccak512 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.Keccak512.ToString()));
        }

        [Test]
        public void RIPEMD160 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.RIPEMD160.ToString()));
        }

        [Test]
        public void SHA1 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.SHA1.ToString()));
        }

        [Test]
        public void SHA256 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.SHA256.ToString()));
        }

        [Test]
        public void SHA512 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.SHA512.ToString()));
        }

        [Test]
        public void Tiger () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.Tiger.ToString()));
        }

        [Test]
        public void Whirlpool () {
            RunMACTest(function, Encoding.UTF8.GetBytes(HashFunctions.Whirlpool.ToString()));
        }
    }
}
