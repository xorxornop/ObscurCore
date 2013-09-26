using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class NOEKEON : BlockCipherTestBase
    {
        public NOEKEON ()
            : base(SymmetricBlockCiphers.NOEKEON, 128, 128) {
        }


    }
}
