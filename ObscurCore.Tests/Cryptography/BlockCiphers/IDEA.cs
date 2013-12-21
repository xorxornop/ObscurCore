using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
#if INCLUDE_IDEA
    class IDEA : BlockCipherTestBase
    {
        public IDEA ()
            : base(SymmetricBlockCipher.Idea, 64, 128) {
        }
    }
#endif
}
