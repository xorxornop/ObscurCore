using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Obscur.Core.Cryptography.Ciphers.Stream;

namespace ObscurCore.Tests.Cryptography.Ciphers.Stream
{
#if DEBUG
    class Null : StreamCipherTestBase
    {
        public Null() : base(StreamCipher.None) { }
    }
#endif
}
