using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    public class AES : BlockCipherTestBase
    {
        public AES() : base(SymmetricBlockCipher.Aes, 128, 128) { }
    }
}
