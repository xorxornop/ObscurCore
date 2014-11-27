using Obscur.Core.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class Camellia : BlockCipherTestBase
    {
        public Camellia() : 
            base(BlockCipher.Camellia) {
        }
    }
}
