using System;

namespace ObscurCore.Cryptography
{
    /// <summary>
    /// This exception is thrown whenever a cipher requires a change of key, iv
    /// or similar after x amount of bytes enciphered
    /// </summary>
    public class MaxBytesExceededException : CryptoException
    {
        private const string ExceptionMessage =
            "Exceeded maximum number of bytes that may be processed before loss of security properties.";

        public MaxBytesExceededException(): base(ExceptionMessage) {}
        public MaxBytesExceededException(string message) : base(message) {}
        public MaxBytesExceededException(string message, Exception inner) : base(message, inner) {}
    }
}