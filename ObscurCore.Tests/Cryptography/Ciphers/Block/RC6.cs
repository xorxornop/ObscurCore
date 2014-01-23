using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    class RC6 : BlockCipherTestBase
    {
        public RC6 ()
            : base(SymmetricBlockCipher.Rc6) {
        }
    }
}
