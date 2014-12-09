using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Block
{
    class Twofish : BlockCipherTestBase
    {
        public Twofish ()
            : base(BlockCipher.Twofish) {
        }
    }
}
