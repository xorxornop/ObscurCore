using System;
using System.Runtime.Serialization;

namespace ObscurCore.Cryptography
{
    [Serializable]
    public class PaddingDataException : CryptoException
    {
        private const string ExceptionMessage =
            "Exceeded maximum number of bytes that may be processed before loss of security properties.";

        public PaddingDataException() : base(ExceptionMessage) {}
        public PaddingDataException(string message) : base(ExceptionMessage + "\n" + message) {}
        public PaddingDataException(string message, Exception inner) : base(message, inner) {}

        protected PaddingDataException(
            SerializationInfo info,
            StreamingContext context) : base(info, context) {}
    }
}