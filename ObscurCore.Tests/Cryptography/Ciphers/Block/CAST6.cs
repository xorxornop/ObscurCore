using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
#if INCLUDE_CAST5AND6
    class CAST6 : BlockCipherTestBase
    {
        public CAST6 ()
            : base(BlockCipher.Cast6) {
        }
    }
#endif
}
