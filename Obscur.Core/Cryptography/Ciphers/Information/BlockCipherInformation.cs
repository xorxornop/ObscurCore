#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System.Collections.Generic;
using System.Linq;
using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Cryptography.Ciphers.Information
{
    /// <summary>
    ///     Information about a block cipher.
    ///     Used to produce a specification of allowed use.
    /// </summary>
    /// <seealso cref="Athena" />
    public sealed class BlockCipherInformation : CipherInformation, IEnumeratedPrimitiveInformation<BlockCipher>
    {
        /// <summary>
        ///     Array of allowable sizes (in bits) for the block size of the cipher.
        /// </summary>
        public int[] AllowableBlockSizesBits { get; internal set; }

        /// <summary>
        ///     Array of allowable sizes (in bytes) for the block size of the cipher.
        /// </summary>
        public IEnumerable<int> AllowableBlockSizes
        {
            get { return AllowableBlockSizesBits.Select(n => n / 8); }
            internal set { AllowableBlockSizesBits = value.Select(n => n * 8).ToArray(); }
        }

        /// <summary>
        ///     If no block size size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultBlockSizeBits { get; internal set; }

        /// <summary>
        ///     If no block size size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultBlockSize
        {
            get { return DefaultBlockSizeBits / 8; }
            internal set { DefaultBlockSizeBits = value * 8; }
        }

        /// <summary>
        ///     Array of allowable sizes (in bits) for the cipher initialisation vector (IV).
        /// </summary>
        public int[] AllowableIvSizesBits { get; internal set; }

        /// <summary>
        ///     Array of allowable sizes (in bytes) for the cipher initialisation vector (IV).
        /// </summary>
        public IEnumerable<int> AllowableIvSizes
        {
            get { return AllowableIvSizesBits.Select(n => n / 8); }
            internal set { AllowableIvSizesBits = value.Select(n => n * 8).ToArray(); }
        }

        /// <summary>
        ///     If no IV size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultIvSizeBits { get; internal set; }

        /// <summary>
        ///     If no IV size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultIvSize
        {
            get { return DefaultIvSizeBits / 8; }
            internal set { DefaultIvSizeBits = value * 8; }
        }

        #region IEnumeratedPrimitiveInformation<BlockCipher> Members

        /// <summary>
        ///     Enumeration member associated with the block cipher.
        /// </summary>
        public BlockCipher Identity { get; internal set; }

        #endregion

        /// <summary>
        ///     Check if a given block <paramref name="size" /> is valid for this cipher.
        /// </summary>
        /// <param name="size">Block size to check.</param>
        /// <param name="bits"><c>True</c> if size is in bits, <c>false</c> if in bytes.</param>
        /// <returns><c>True</c> if block size is valid, <c>false</c> if invalid.</returns>
        public bool IsBlockSizeInSpecification(int size, bool bits = true)
        {
            return AllowableBlockSizesBits.Contains(bits ? size : size.BytesToBits());
        }

        /// <summary>
        ///     Check if a given IV <paramref name="size" /> is valid for this cipher.
        /// </summary>
        /// <param name="size">IV size to check.</param>
        /// <param name="bits"><c>True</c> if size is in bits, <c>false</c> if in bytes.</param>
        /// <returns><c>True</c> if IV size is valid, <c>false</c> if invalid.</returns>
        public bool IsIvSizeInSpecification(int size, bool bits = true)
        {
            return AllowableIvSizesBits.Contains(bits ? size : size.BytesToBits());
        }

        public override int MaximumOutputSizeDifference(bool encrypting)
        {
            return AllowableBlockSizes.Last() * (encrypting ? 1 : -1);
        }
    }
}
