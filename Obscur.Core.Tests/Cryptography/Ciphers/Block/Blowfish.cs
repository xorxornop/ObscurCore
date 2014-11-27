using Obscur.Core.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    internal class Blowfish : BlockCipherTestBase
    {
        public Blowfish () : base(BlockCipher.Blowfish) { }
    }
}
