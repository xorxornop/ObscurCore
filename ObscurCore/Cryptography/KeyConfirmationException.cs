using System;

namespace ObscurCore.Cryptography
{
    public class KeyConfirmationException : Exception
    {
        private const string ExceptionMessage = "Key confirmation failed for an unspecified reason.";

        public KeyConfirmationException() : base(ExceptionMessage) {}
        public KeyConfirmationException(string message) : base(message) {}
        public KeyConfirmationException(string message, Exception inner) : base(message, inner) {}
    }
}