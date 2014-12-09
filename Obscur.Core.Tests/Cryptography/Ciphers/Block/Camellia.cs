using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Block
{
    class Camellia : BlockCipherTestBase
    {
        public Camellia() : 
            base(BlockCipher.Camellia) {
        }
    }
}
