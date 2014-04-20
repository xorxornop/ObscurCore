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
            RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Aes.ToString()));
        }

        [Test]
        public void CMAC_Blowfish () {
            RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Blowfish.ToString()));
        }

        [Test]
        public void CMAC_Camellia () {
            RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Camellia.ToString()), null, CreateRandomBytes(256));
        }
#if INCLUDE_CAST5AND6
        [Test]
        public void CMAC_CAST5 () {
            RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Cast5.ToString()));
        }

        [Test]
        public void CMAC_CAST6 () {
             RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Cast6.ToString()), null, CreateRandomBytes(256));
        }
#endif
        [Test]
        public void CMAC_IDEA () {
			RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Idea.ToString()));
        }

        [Test]
        public void CMAC_NOEKEON () {
			RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Noekeon.ToString()));
        }

        [Test]
        public void CMAC_RC6 () {
			RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Rc6.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_Serpent () {
			RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Serpent.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_Twofish () {
			RunMACTest(function, Encoding.UTF8.GetBytes(BlockCipher.Twofish.ToString()), null, CreateRandomBytes(256));
        }
    }
}
