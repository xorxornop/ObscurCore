using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class Twofish : BlockCipherTestBase
    {
        public Twofish ()
            : base(SymmetricBlockCiphers.Twofish, 128, 256) {
        }
    }
}
