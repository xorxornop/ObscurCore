using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class RC6 : BlockCipherTestBase
    {
        public RC6 ()
            : base(SymmetricBlockCiphers.RC6, 128, 256) {
        }
    }
}
