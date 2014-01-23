using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class Camellia : BlockCipherTestBase
    {
        public Camellia() : 
            base(SymmetricBlockCipher.Camellia) {
        }
    }
}
