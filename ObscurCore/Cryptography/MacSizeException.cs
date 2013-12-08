using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace ObscurCore.Cryptography
{
    [Serializable]
    public class MacSizeException : Exception
    {
        public MacSizeException() {
            RequestedSize = null;
            Mode = null;
            AllowedSizes = null;
        }
        public MacSizeException(string message) : base(message) {
            RequestedSize = null;
            Mode = null;
            AllowedSizes = null;
        }
        public MacSizeException(string message, Exception inner) : base(message, inner) {
            RequestedSize = null;
            Mode = null;
            AllowedSizes = null;
        }

        protected MacSizeException(SerializationInfo info, StreamingContext context) : base(info, context) {}

        public MacSizeException(AeadBlockCipherMode modeEnum, int requestedSizeBits)
            : base(String.Format("The size {0} is not supported for use with the {1} mode.", requestedSizeBits, 
                Athena.Cryptography.AeadBlockCipherModes[modeEnum].DisplayName))
        {
            RequestedSize = requestedSizeBits;
            Mode = modeEnum;
            AllowedSizes = Athena.Cryptography.AeadBlockCipherModes[modeEnum].AllowableBlockSizes.ToList();
        }

        /// <summary>
        /// Size of MAC in bits requested that triggered the exception. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public int? RequestedSize { get; private set; }

        /// <summary>
        /// Mode of AEAD operation enacting the restriction. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public AeadBlockCipherMode? Mode { get; private set; }

        /// <summary>
        /// Allowed sizes of MAC for the relevant mode. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public IReadOnlyList<int> AllowedSizes { get; private set; } 
    }
}