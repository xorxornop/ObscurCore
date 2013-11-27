using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class CAST6 : BlockCipherTestBase
    {
        public CAST6 ()
            : base(SymmetricBlockCipher.Cast6, 128, 256) {
        }
    }
}
