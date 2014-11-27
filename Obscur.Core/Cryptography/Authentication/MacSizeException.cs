using System;

namespace Obscur.Core.Cryptography.Authentication
{
    public class MacSizeException : Exception
    {
        public MacSizeException() {
        }
        public MacSizeException(string message) : base(message) {
        }
        public MacSizeException(string message, Exception inner) : base(message, inner) {
        }
    }
}
