using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography;

namespace ObscurCore.Tests.Cryptography.BlockCiphers
{
#if(INCLUDE_GOST28147)
    class GOST28147 : BlockCipherTestBase
    {
        public GOST28147 ()
            : base(SymmetricBlockCiphers.GOST28147, 64, 256) {
        }

        [Test]
        public override void GCM () {
            // Using default block & key size
            AEADCipherConfiguration config = null;

            Assert.Throws<MACSizeException>(() => config =
                new AEADCipherConfiguration(_blockCipher, AEADBlockCipherModes.GCM, BlockCipherPaddings.None, _defaultKeySize, _defaultBlockSize),
                "GCM mode incompatible with " + _defaultBlockSize + " bit block size!");
            //RunEqualityTest(config);
        }
    }
#endif
}
