using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
    class Rijndael : BlockCipherTestBase
    {
        public Rijndael ()
            : base(SymmetricBlockCiphers.Rijndael, 128, 256) {
        }
    }
}
