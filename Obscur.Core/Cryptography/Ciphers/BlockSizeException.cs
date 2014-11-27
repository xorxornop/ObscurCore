using System;
using System.Collections.Generic;
using System.Linq;
using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Cryptography.Ciphers
{
    public class BlockSizeException : ConfigurationInvalidException
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

        public BlockSizeException(BlockCipher cipherEnum, int requestedSizeBits)
            : base(String.Format("The size {0} is not supported for use with the {1} cipher.", requestedSizeBits, 
                Athena.Cryptography.BlockCiphers[cipherEnum].DisplayName))
        {
            RequestedSize = requestedSizeBits;
            Mode = cipherEnum;
            AllowedSizes = Athena.Cryptography.BlockCiphers[cipherEnum].AllowableBlockSizesBits.ToList();
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
        public BlockCipher? Mode { get; private set; }

        /// <summary>
        /// Allowed sizes of MAC for the relevant mode. 
        /// Null if caller has not supplied this data.
        /// </summary>
        public IReadOnlyList<int> AllowedSizes { get; private set; } 
    }
}