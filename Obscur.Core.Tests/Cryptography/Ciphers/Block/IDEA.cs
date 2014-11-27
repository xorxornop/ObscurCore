using Obscur.Core.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
#if INCLUDE_IDEA
    class IDEA : BlockCipherTestBase
    {
        public IDEA ()
            : base(BlockCipher.Idea) {
        }
    }
#endif
}
