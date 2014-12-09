using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Block
{
    internal class AES : BlockCipherTestBase
    {
		public AES() : base(BlockCipher.Aes) { }
    }
}
