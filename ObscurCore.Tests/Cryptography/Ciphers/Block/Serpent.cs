using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class Serpent : BlockCipherTestBase
    {
        public Serpent ()
            : base(SymmetricBlockCipher.Serpent) {
        }
    }
}
