using Obscur.Core.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class Twofish : BlockCipherTestBase
    {
        public Twofish ()
            : base(BlockCipher.Twofish) {
        }
    }
}
