using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    public class AES : BlockCipherTestBase
    {
		public AES() : base(SymmetricBlockCipher.Aes) { }
    }
}
