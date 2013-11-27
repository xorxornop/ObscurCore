using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging.Serialisation
{
	public class CipherConfiguration : SerialisationTestBase
	{
		[Test]
		public void BlockCipher() {
            var inputObj = new SymmetricCipherConfiguration() {
                Type = SymmetricCipherType.Block,
                CipherName = "AES",
                KeySize = 128,
                IV = new byte[] { 0x01, 0x02, 0x03 },
                ModeName = BlockCipherMode.Ctr.ToString(),
                BlockSize = 128,
                PaddingName = BlockCipherPadding.None.ToString()
            };

			var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
			var outputObj = DeserialiseFromMemory<SymmetricCipherConfiguration>(stream);

		    bool equal = inputObj.Equals(outputObj);

			Assert.IsTrue (equal);
		}

        [Test]
        public void AEADBlockCipher () {
            var inputObj = new SymmetricCipherConfiguration() {
                Type = SymmetricCipherType.AEAD,
                CipherName = "AES",
                KeySize = 128,
                IV = new byte[] { 0x01, 0x02, 0x03 },
                ModeName = AeadBlockCipherMode.Gcm.ToString(),
                BlockSize = 128,
                PaddingName = BlockCipherPadding.None.ToString(),
                AssociatedData = new byte[] { 0x03, 0x01, 0x04 },
                MacSize = 128,

            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<SymmetricCipherConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void StreamCipher () {
            var inputObj = new SymmetricCipherConfiguration() {
                Type = SymmetricCipherType.Stream,
                CipherName = "Salsa20",
                KeySize = 256,
                IV = new byte[] { 0x01, 0x02, 0x03 }
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<SymmetricCipherConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }


	}
}
