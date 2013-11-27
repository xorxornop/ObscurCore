using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class NOEKEON : BlockCipherTestBase
    {
        public NOEKEON ()
            : base(SymmetricBlockCipher.Noekeon, 128, 128) {
        }


    }
}
