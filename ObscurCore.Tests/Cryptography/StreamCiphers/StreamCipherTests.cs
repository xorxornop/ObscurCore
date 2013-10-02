using ObscurCore.Cryptography;
using NUnit.Framework;

namespace ObscurCore.Tests.Cryptography.StreamCiphers
{
    class StreamCipherTests : CryptoTestBase
    {
		public StreamCipherTests ()
		{
			SetRandomFixtureKey(256);
		}

        [Test]
        public void HC128 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.HC128);
            RunEqualityTest(config, CreateRandomKey(128));
        }

        [Test]
        public void HC256 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.HC256);
            RunEqualityTest(config);
        }

        [Test]
        public void ISAAC () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.ISAAC);
            RunEqualityTest(config);
        }

        [Test]
        public void Rabbit () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.Rabbit);
            RunEqualityTest(config, CreateRandomKey(128));
        }

#if(INCLUDE_RC4)
        [Test]
        public void RC4_96 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.RC4, 96) { IV = CreateRandomKey(96) };
            RunEqualityTest(config, CreateRandomKey(96));
        }

        [Test]
        public void RC4_128 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.RC4, 128) { IV = CreateRandomKey(128) };
            RunEqualityTest(config, CreateRandomKey(128));
        }
#endif

        [Test]
        public void Salsa20_256 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.Salsa20);
            RunEqualityTest(config);
        }

        [Test]
        public void SOSEMANUK () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.SOSEMANUK);
            RunEqualityTest(config);
        }

#if(INCLUDE_VMPC)
        [Test]
        public void VMPC_256 () {
            var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.VMPC) { IV = CreateRandomKey(256) };
            RunEqualityTest(config);
        }
#endif
    }
}
