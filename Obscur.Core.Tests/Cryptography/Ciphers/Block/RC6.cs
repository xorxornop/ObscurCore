using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Block
{
    class RC6 : BlockCipherTestBase
    {
        public RC6 ()
            : base(BlockCipher.Rc6) {
        }
    }
}
