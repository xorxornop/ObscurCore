using System.IO;
using NUnit.Framework;
using Obscur.Core.Cryptography.Ciphers.Block;
using Obscur.Core.Cryptography.Ciphers.Stream;
using Obscur.Core.DTO;

namespace ObscurCore.Tests.Packaging.Serialisation
{
	public class SymmetricCipherConfiguration : SerialisationTestBase
	{
		[Test]
		public void BlockCipherConfiguration() {
            var inputObj = new CipherConfiguration() {
                Type = CipherType.Block,
                CipherName = BlockCipher.Aes.ToString(),
                KeySizeBits = 128,
                InitialisationVector = new byte[] { 0x01, 0x02, 0x03 },
                ModeName = BlockCipherMode.Ctr.ToString(),
                BlockSizeBits = 128,
                PaddingName = BlockCipherPadding.None.ToString()
            };

			var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
			var outputObj = DeserialiseFromMemory<CipherConfiguration>(stream);

			Assert.IsTrue (inputObj.Equals(outputObj));
		}

        [Test]
        public void StreamCipherConfiguration() {
            var inputObj = new CipherConfiguration() {
                Type = CipherType.Stream,
                CipherName = StreamCipher.Salsa20.ToString(),
                KeySizeBits = 256,
                InitialisationVector = new byte[] { 0x01, 0x02, 0x03 }
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<CipherConfiguration>(stream);

            Assert.IsTrue(inputObj.Equals(outputObj));
        }
	}
}
