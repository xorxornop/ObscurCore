using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class Serpent : BlockCipherTestBase
    {
        public Serpent ()
            : base(SymmetricBlockCipher.Serpent, 128, 256) {
        }
    }
}
