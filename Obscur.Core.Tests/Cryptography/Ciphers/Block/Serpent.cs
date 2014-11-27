using Obscur.Core.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class Serpent : BlockCipherTestBase
    {
        public Serpent ()
            : base(BlockCipher.Serpent) {
        }
    }
}
