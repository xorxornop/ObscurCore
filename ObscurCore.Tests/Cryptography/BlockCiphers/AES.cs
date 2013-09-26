using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    public class AES : BlockCipherTestBase
    {
        public AES() : base(SymmetricBlockCiphers.AES, 128, 128) { }
    }
}
