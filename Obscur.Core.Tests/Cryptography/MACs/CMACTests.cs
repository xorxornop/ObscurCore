using System.Text;
using NUnit.Framework;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.MACs
{
    class CMACTests : MacTestBase
    {
        const MacFunction function = MacFunction.Cmac;

        public CMACTests() {
            SetRandomFixtureParameters(128);
        }

        [Test]
        public void CMAC_AES () {
            RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Aes.ToString()));
        }

        [Test]
        public void CMAC_Blowfish () {
            RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Blowfish.ToString()));
        }

        [Test]
        public void CMAC_Camellia () {
            RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Camellia.ToString()), null, CreateRandomBytes(256));
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
			RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Idea.ToString()));
        }

        [Test]
        public void CMAC_NOEKEON () {
			RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Noekeon.ToString()));
        }

        [Test]
        public void CMAC_RC6 () {
			RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Rc6.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_Serpent () {
			RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Serpent.ToString()), null, CreateRandomBytes(256));
        }

        [Test]
        public void CMAC_Twofish () {
			RunMacTest(function, Encoding.UTF8.GetBytes(BlockCipher.Twofish.ToString()), null, CreateRandomBytes(256));
        }
    }
}
