using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Block
{
    class Serpent : BlockCipherTestBase
    {
        public Serpent ()
            : base(BlockCipher.Serpent) {
        }
    }
}
