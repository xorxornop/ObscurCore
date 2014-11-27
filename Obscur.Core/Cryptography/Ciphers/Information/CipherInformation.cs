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

namespace Obscur.Core.Cryptography.Ciphers.Information
{
    /// <summary>
    ///     Base class for Information about a cryptographic cipher.
    ///     Used to produce a specification of allowed use.
    /// </summary>
    public abstract class CipherInformation : IPrimitiveInformation
    {
        /// <summary>
        ///     Array of allowable sizes (in bits) for the size of the the cryptographic key for the cipher.
        /// </summary>
        public int[] AllowableKeySizesBits { get; internal set; }

        /// <summary>
        ///     Array of allowable sizes (in bytes) for the size of the the cryptographic key for the cipher.
        /// </summary>
        public IEnumerable<int> AllowableKeySizes
        {
            get { return AllowableKeySizesBits.Select(n => n / 8); }
            internal set { AllowableKeySizesBits = value.Select(n => n * 8).ToArray(); }
        }

        /// <summary>
        ///     If no key size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultKeySizeBits { get; internal set; }

        /// <summary>
        ///     If no key size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultKeySize
        {
            get { return DefaultKeySizeBits / 8; }
            internal set { DefaultKeySizeBits = value * 8; }
        }

        #region IPrimitiveInformation Members

        /// <summary>
        ///     Name of the cryptographic cipher transform.
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        ///     Name to show a user or for a detailed specification.
        /// </summary>
        public string DisplayName { get; internal set; }

        #endregion

        /// <summary>
        ///     Check if a given key <paramref name="size" /> is valid for this cipher.
        /// </summary>
        /// <param name="size">Size of the key.</param>
        /// <param name="bits"><c>True</c> if size is in bits, <c>false</c> if in bytes.</param>
        /// <returns><c>True</c> if key size is valid, <c>false</c> if invalid.</returns>
        public bool IsKeySizeInSpecification(int size, bool bits = true)
        {
            return AllowableKeySizesBits.Contains(bits ? size : size.BytesToBits());
        }

        /// <summary>
        ///     The maximum size (in bytes) that the output may differ from the input. 
        ///     A positive number indicates expansion - a negative, contraction.
        /// </summary>
        /// <param name="encrypting"></param>
        /// <returns></returns>
        public virtual int MaximumOutputSizeDifference(bool encrypting)
        {
            return 0;
        }
    }
}
