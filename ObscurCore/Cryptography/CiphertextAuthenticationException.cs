using System;
using System.Runtime.Serialization;

namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Represents the error that occurs when a ciphertext authentication through AEAD mechanism fails.
    /// </summary>
    [Serializable]
    public class CiphertextAuthenticationException : CryptoException
    {
        private const string ExceptionAttention = "CAUTION: Possible impersonation attempt!";

        public CiphertextAuthenticationException() : base(ExceptionAttention) {}
        public CiphertextAuthenticationException(string message) : base(ExceptionAttention + "\n" + message) {}
        public CiphertextAuthenticationException(string message, Exception inner) : base(message, inner) {}

        protected CiphertextAuthenticationException(
            SerializationInfo info,
            StreamingContext context) : base(info, context) {}
    }
}