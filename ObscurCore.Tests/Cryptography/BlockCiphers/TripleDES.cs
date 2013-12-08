using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class TripleDES : BlockCipherTestBase
    {
        public TripleDES ()
            : base(SymmetricBlockCipher.TripleDes, 64, 192) {
        }

        [Test]
        public override void GCM () {
            // Using default block & key size
            SymmetricCipherConfiguration config = null;

            Assert.Throws<MacSizeException>(() => config =
                SymmetricCipherConfigurationFactory.CreateAeadBlockCipherConfiguration(BlockCipher, AeadBlockCipherMode.Gcm, BlockCipherPadding.None, _defaultKeySize, _defaultBlockSize, null),
                "GCM mode incompatible with " + _defaultBlockSize + " bit block size!");
            //RunEqualityTest(config);
        }
    }
}
