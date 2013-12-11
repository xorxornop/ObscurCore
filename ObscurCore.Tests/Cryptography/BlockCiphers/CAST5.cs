using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class CAST5 : BlockCipherTestBase
    {
        public CAST5 ()
            : base(SymmetricBlockCipher.Cast5, 64, 128) {
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
