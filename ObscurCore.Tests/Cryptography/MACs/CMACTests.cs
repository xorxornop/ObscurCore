using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.MACs
{
    class CMACTests : MACTestBase
    {
        const MacFunction function = MacFunction.Cmac;

        public CMACTests() {
            SetRandomFixtureParameters(128);
        }

        [Test]
        public void CMAC_AES () {
            RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Aes.ToString()));
        }

        [Test]
        public void CMAC_Blowfish () {
            RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Blowfish.ToString()));
        }

        [Test]
        public void CMAC_Camellia () {
            RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Camellia.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_CAST5 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Cast5.ToString()));
        }

        [Test]
        public void CMAC_CAST6 () {
             RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Cast6.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_IDEA () {
			RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Idea.ToString()));
        }

        [Test]
        public void CMAC_NOEKEON () {
			RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Noekeon.ToString()));
        }

        [Test]
        public void CMAC_RC6 () {
			RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Rc6.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_Serpent () {
			RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Serpent.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_Twofish () {
			RunMACTest(function, Encoding.UTF8.GetBytes(SymmetricBlockCipher.Twofish.ToString()), null, CreateRandomBytes(256));
        }
    }
}
