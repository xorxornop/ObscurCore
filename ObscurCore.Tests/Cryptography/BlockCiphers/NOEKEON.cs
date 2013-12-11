using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class NOEKEON : BlockCipherTestBase
    {
        public NOEKEON ()
            : base(SymmetricBlockCipher.Noekeon, 128, 128) {
        }


    }
}
