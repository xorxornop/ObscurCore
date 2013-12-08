using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace ObscurCore.Cryptography
{
    [Serializable]
    public class KeySizeException : Exception
    {
        public KeySizeException() {
            RequestedSize = null;
            Cipher = null;
            AllowedSizes = null;
        }
        public KeySizeException(string message) : base(message) {
            RequestedSize = null;
            Cipher = null;
            AllowedSizes = null;
        }
        public KeySizeException(string message, Exception inner) : base(message, inner) {
            RequestedSize = null;
            Cipher = null;
            AllowedSizes = null;
        }

        protected KeySizeException(SerializationInfo info, StreamingContext context) : base(info, context) {}

        public KeySizeException(SymmetricBlockCipher cipherEnum, int requestedSizeBits)
            : this(cipherEnum.ToString(), requestedSizeBits, Athena.Cryptography.BlockCiphers[cipherEnum].AllowableKeySizes.ToList()) {}

        public KeySizeException(SymmetricStreamCipher cipherEnum, int requestedSizeBits)
            : this(cipherEnum.ToString(), requestedSizeBits, Athena.Cryptography.StreamCiphers[cipherEnum].AllowableKeySizes.ToList()) {}

        protected KeySizeException(string cipherName, int requestedSizeBits, List<int> allowedSizes)
            : base(String.Format("The size {0} is not supported for use with the {1} cipher.", requestedSizeBits, 
                cipherName))
        {
            RequestedSize = requestedSizeBits;
            Cipher = cipherName;
            AllowedSizes = allowedSizes;
        }

        /// <summary>
        /// Size of block in bits requested that triggered the exception. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public int? RequestedSize { get; private set; }

        /// <summary>
        /// Name of cipher enacting the restriction. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public string Cipher { get; private set; }

        /// <summary>
        /// Allowed sizes of key. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public IReadOnlyList<int> AllowedSizes { get; private set; } 
    }
}