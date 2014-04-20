using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
#if INCLUDE_CAST5AND6
    class CAST5 : BlockCipherTestBase
    {
        public CAST5 ()
            : base(BlockCipher.Cast5) {
        }
    }
#endif
}
