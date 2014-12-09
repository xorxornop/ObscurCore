using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Block
{
    internal class Blowfish : BlockCipherTestBase
    {
        public Blowfish () : base(BlockCipher.Blowfish) { }
    }
}
