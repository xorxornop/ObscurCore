using System;
using System.Runtime.Serialization;

namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Represents an error occuring during a cryptographic operation.
    /// </summary>
    [Serializable]
    public class CryptoException : Exception
    {
        private const string ExceptionMessage =
            "Unspecified cryptography error; it may have been redacted for security.";

        public CryptoException() : base(ExceptionMessage) {}
        public CryptoException(string message) : base(message) {}
        public CryptoException(string message, Exception inner) : base(message, inner) {}

        protected CryptoException(
            SerializationInfo info,
            StreamingContext context) : base(info, context) {}
    }
}