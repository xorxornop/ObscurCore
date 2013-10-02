using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    public class Blowfish : BlockCipherTestBase
    {
        public Blowfish () : base(SymmetricBlockCiphers.Blowfish, 64, 128) { }

        [Test]
        public override void GCM () {
            // Using default block & key size
            SymmetricCipherConfiguration config = null;

            Assert.Throws<MACSizeException>(() => config =
                SymmetricCipherConfigurationFactory.CreateAEADBlockCipherConfiguration(_blockCipher, AEADBlockCipherModes.GCM, BlockCipherPaddings.None, _defaultKeySize, _defaultBlockSize), 
                "GCM mode incompatible with " + _defaultBlockSize + " bit block size!");
            //RunEqualityTest(config);
        }
    }
}
