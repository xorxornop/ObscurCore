using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Cryptography
{
    [Serializable]
    public class BlockSizeException : Exception
    {
        public BlockSizeException() {
            RequestedSize = null;
            Mode = null;
            AllowedSizes = null;
        }
        public BlockSizeException(string message) : base(message) {
            RequestedSize = null;
            Mode = null;
            AllowedSizes = null;
        }
        public BlockSizeException(string message, Exception inner) : base(message, inner) {
            RequestedSize = null;
            Mode = null;
            AllowedSizes = null;
        }

        protected BlockSizeException(SerializationInfo info, StreamingContext context) : base(info, context) {}

        public BlockSizeException(SymmetricBlockCipher cipherEnum, int requestedSizeBits)
            : base(String.Format("The size {0} is not supported for use with the {1} cipher.", requestedSizeBits, 
                Athena.Cryptography.BlockCiphers[cipherEnum].DisplayName))
        {
            RequestedSize = requestedSizeBits;
            Mode = cipherEnum;
            AllowedSizes = Athena.Cryptography.BlockCiphers[cipherEnum].AllowableBlockSizes.ToList();
        }

        /// <summary>
        /// Size of block in bits requested that triggered the exception. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public int? RequestedSize { get; private set; }

        /// <summary>
        /// Mode of AEAD operation enacting the restriction. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public SymmetricBlockCipher? Mode { get; private set; }

        /// <summary>
        /// Allowed sizes of MAC for the relevant mode. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public IReadOnlyList<int> AllowedSizes { get; private set; } 
    }
}