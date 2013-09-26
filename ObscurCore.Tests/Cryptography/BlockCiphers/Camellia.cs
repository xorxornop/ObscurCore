using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class Camellia : BlockCipherTestBase
    {
        public Camellia() : 
            base(SymmetricBlockCiphers.Camellia, 128, 256) {
        }
    }
}
