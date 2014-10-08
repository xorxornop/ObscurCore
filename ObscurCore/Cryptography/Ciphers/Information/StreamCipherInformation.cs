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
using ObscurCore.Cryptography.Ciphers.Stream;

namespace ObscurCore.Cryptography.Ciphers.Information
{
    /// <summary>
    /// </summary>
    public sealed class StreamCipherInformation : CipherInformation, IEnumeratedPrimitiveInformation<StreamCipher>
    {
        /// <summary>
        ///     Array of allowable sizes (in bits) for the cipher nonce.
        /// </summary>
        public int[] AllowableNonceSizesBits { get; internal set; }

        /// <summary>
        ///     Array of allowable sizes (in bytes) for the cipher nonce.
        /// </summary>
        public IEnumerable<int> AllowableIvSizes
        {
            get { return AllowableNonceSizesBits.Select(n => n / 8); }
            internal set { AllowableNonceSizesBits = value.Select(n => n * 8).ToArray(); }
        }

        /// <summary>
        ///     If no nonce size is supplied when configuring the cipher,
        ///     this is the size that should be used.
        /// </summary>
        public int DefaultNonceSizeBits { get; internal set; }

        /// <summary>
        ///     If no nonce size is supplied when configuring the cipher,
        ///     this is the size that should be used.
        /// </summary>
        public int DefaultNonceSize
        {
            get { return DefaultNonceSizeBits / 8; }
            internal set { DefaultNonceSizeBits = value * 8; }
        }

        #region IEnumeratedPrimitiveInformation<StreamCipher> Members

        /// <summary>
        ///     Enumeration member associated with the stream cipher.
        /// </summary>
        public StreamCipher Identity { get; internal set; }

        #endregion

        /// <summary>
        ///     Check if a given nonce <paramref name="size" /> is valid for this cipher.
        /// </summary>
        /// <param name="size">Nonce size to check.</param>
        /// <param name="bits"><c>True</c> if size is in bits, <c>false</c> if in bytes.</param>
        /// <returns><c>True</c> if nonce size is valid, <c>false</c> if invalid.</returns>
        public bool IsNonceSizeInSpecification(int size, bool bits = true)
        {
            return AllowableNonceSizesBits.Contains(bits ? size : size.BytesToBits());
        }
    }
}
