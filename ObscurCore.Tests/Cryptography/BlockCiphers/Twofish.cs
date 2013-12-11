using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class Twofish : BlockCipherTestBase
    {
        public Twofish ()
            : base(SymmetricBlockCipher.Twofish, 128, 256) {
        }
    }
}
