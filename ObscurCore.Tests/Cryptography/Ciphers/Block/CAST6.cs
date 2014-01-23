using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class CAST6 : BlockCipherTestBase
    {
        public CAST6 ()
            : base(SymmetricBlockCipher.Cast6) {
        }
    }
}
