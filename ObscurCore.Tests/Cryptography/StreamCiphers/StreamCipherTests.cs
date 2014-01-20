using ObscurCore.Cryptography;
using NUnit.Framework;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Tests.Cryptography.StreamCiphers
{
    class StreamCipherTests : CipherTestBase
    {
		public StreamCipherTests ()
		{
			SetRandomFixtureKey(256);
		}

        [Test]
        public void HC128 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Hc128);
            RunEqualityTest(config, CreateRandomKey(128));
        }

        [Test]
        public void HC256 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Hc256);
            RunEqualityTest(config);
        }

#if(INCLUDE_ISAAC)
        [Test]
        public void ISAAC () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.ISAAC);
            RunEqualityTest(config);
        }
#endif

        [Test]
        public void Rabbit () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Rabbit);
            RunEqualityTest(config, CreateRandomKey(128));
        }

#if(INCLUDE_RC4)
        [Test]
        public void RC4_96 () {
			var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Rc4, 96);
			RunEqualityTest(config, CreateRandomKey(96));
        }

        [Test]
        public void RC4_128 () {
			var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Rc4, 128);
            RunEqualityTest(config, CreateRandomKey(128));
        }
#endif

        [Test]
        public void Salsa20_256 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Salsa20);
            RunEqualityTest(config);
        }

		[Test]
		public void XSalsa20_256 () {
			var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.XSalsa20);
			RunEqualityTest(config);
		}

        [Test]
        public void SOSEMANUK () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Sosemanuk);
            RunEqualityTest(config);
        }
    }
}
