using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class CAST5 : BlockCipherTestBase
    {
        public CAST5 ()
            : base(SymmetricBlockCipher.Cast5) {
        }
    }
}
