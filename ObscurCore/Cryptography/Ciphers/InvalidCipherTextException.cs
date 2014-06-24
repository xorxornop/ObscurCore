using System;

namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    ///     Exception to be thrown on the event of invalid or unexpected ciphertext.
    /// </summary>
    public class InvalidCipherTextException
        : CryptoException
    {
        public InvalidCipherTextException() {}

        public InvalidCipherTextException(
            string message)
            : base(message) {}

        public InvalidCipherTextException(
            string message,
            Exception exception)
            : base(message, exception) {}
    }
}
