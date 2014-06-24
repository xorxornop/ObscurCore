using System;
using System.Runtime.Serialization;

namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Represents the error that occurs when a ciphertext authentication fails.
    /// </summary>
    public class CiphertextAuthenticationException : CryptoException
    {
        private const string ExceptionAttention = "CAUTION: Possible impersonation attempt!";

        public CiphertextAuthenticationException() : base(ExceptionAttention) {}
        public CiphertextAuthenticationException(string message) : base(ExceptionAttention + "\n" + message) {}
        public CiphertextAuthenticationException(string message, Exception inner) : base(message, inner) {}
    }
}