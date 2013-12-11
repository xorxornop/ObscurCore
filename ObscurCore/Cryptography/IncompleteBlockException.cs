using System;
using System.Runtime.Serialization;

namespace ObscurCore.Cryptography
{
    [Serializable]
    public class IncompleteBlockException : CryptoException
    {
        private const string ExceptionMessage =
            "The ciphertext data is not the expected length for the block size.";

        public IncompleteBlockException() : base(ExceptionMessage) {}
        public IncompleteBlockException(string message) : base(ExceptionMessage + "\n" + message) {}
        public IncompleteBlockException(string message, Exception inner) : base(message, inner) {}

        protected IncompleteBlockException(
            SerializationInfo info,
            StreamingContext context) : base(info, context) {}
    }
}