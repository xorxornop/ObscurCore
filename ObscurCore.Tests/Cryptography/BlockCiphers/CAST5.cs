using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class CAST5 : BlockCipherTestBase
    {
        public CAST5 ()
            : base(SymmetricBlockCipher.Cast5, 64, 128) {
        }
    }
}
