using NUnit.Framework;
using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    public class Blowfish : BlockCipherTestBase
    {
        public Blowfish () : base(SymmetricBlockCiphers.Blowfish, 64, 128) { }

        [Test]
        public override void GCM () {
            // Using default block & key size
            AEADCipherConfiguration config = null;

            Assert.Throws<MACSizeException>(() => config =
                new AEADCipherConfiguration(_blockCipher, AEADBlockCipherModes.GCM, BlockCipherPaddings.None, _defaultKeySize, _defaultBlockSize), 
                "GCM mode incompatible with " + _defaultBlockSize + " bit block size!");
            //RunEqualityTest(config);
        }
    }
}
