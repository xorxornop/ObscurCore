using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
    public class Blowfish : BlockCipherTestBase
    {
        public Blowfish () : base(SymmetricBlockCipher.Blowfish) { }
    }
}
