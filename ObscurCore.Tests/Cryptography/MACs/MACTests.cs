using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.MACs
{
    class MACTests : MACTestBase
    {
        public MACTests() {
            SetRandomFixtureParameters(256);
        }

        [Test]
        public void BLAKE2B256 () {
            RunMACTest(MACFunctions.BLAKE2B256, null, null, CreateRandomBytes(128));
        }

        [Test]
        public void BLAKE2B384 () {
            RunMACTest(MACFunctions.BLAKE2B384, null, CreateRandomBytes(384), CreateRandomBytes(128));
        }

        [Test]
        public void BLAKE2B512 () {
            RunMACTest(MACFunctions.BLAKE2B512, null, CreateRandomBytes(512), CreateRandomBytes(128));
        }

        [Test]
        public void Keccak224 () {
            RunMACTest(MACFunctions.Keccak224);
        }

        [Test]
        public void Keccak256 () {
            RunMACTest(MACFunctions.Keccak256);
        }

        [Test]
        public void Keccak384 () {
            RunMACTest(MACFunctions.Keccak384);
        }

        [Test]
        public void Keccak512 () {
            RunMACTest(MACFunctions.Keccak512);
        }
    }
}
