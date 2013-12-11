using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class RC6 : BlockCipherTestBase
    {
        public RC6 ()
            : base(SymmetricBlockCipher.Rc6, 128, 256) {
        }
    }
}
