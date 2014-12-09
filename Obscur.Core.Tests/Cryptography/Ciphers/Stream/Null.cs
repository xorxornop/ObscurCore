using Obscur.Core.Cryptography.Ciphers.Stream;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Stream
{
#if DEBUG
    class Null : StreamCipherTestBase
    {
        public Null() : base(StreamCipher.None) { }
    }
#endif
}
