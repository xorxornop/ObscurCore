using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class TripleDES : BlockCipherTestBase
    {
        public TripleDES ()
            : base(SymmetricBlockCipher.TripleDes, 64, 192) {
        }
    }
}
