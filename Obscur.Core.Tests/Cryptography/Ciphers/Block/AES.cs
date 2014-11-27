using Obscur.Core.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    internal class AES : BlockCipherTestBase
    {
		public AES() : base(BlockCipher.Aes) { }
    }
}
