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
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.HC128);
            RunEqualityTest(config, CreateRandomKey(128));
        }

        [Test]
        public void HC256 () {
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.HC256);
            RunEqualityTest(config);
        }

        [Test]
        public void Rabbit () {
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.Rabbit);
            RunEqualityTest(config, CreateRandomKey(128));
        }

        /*[Test]
        public void RC4_96 () {
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.RC4, 96) { IV = CreateRandomKey(96) };
            RunEqualityTest(config, CreateRandomKey(96));
        }

        [Test]
        public void RC4_128 () {
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.RC4, 128) { IV = CreateRandomKey(128) };
            RunEqualityTest(config, CreateRandomKey(128));
        }*/

        [Test]
        public void Salsa20_256 () {
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.Salsa20);
            RunEqualityTest(config);
        }

        [Test]
        public void SOSEMANUK () {
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.SOSEMANUK);
            RunEqualityTest(config);
        }

        /*[Test]
        public void VMPC_256 () {
            var config = new StreamCipherConfiguration(SymmetricStreamCiphers.VMPC) { IV = CreateRandomKey(256) };
            RunEqualityTest(config);
        }*/
    }
}
