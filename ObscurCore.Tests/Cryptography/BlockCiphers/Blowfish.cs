using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    public class Blowfish : BlockCipherTestBase
    {
        public Blowfish () : base(SymmetricBlockCipher.Blowfish, 64, 128) { }
    }
}
