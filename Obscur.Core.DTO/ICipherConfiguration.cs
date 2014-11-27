#region License

// 	Copyright 2013-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

#endregion

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Interface for a configuration for a symmetric cipher.
    /// </summary>
    public interface ICipherConfiguration
    {
        /// <summary>
        ///     Category/type of the cipher primitive, e.g. block or stream.
        /// </summary>
        CipherType Type { get; }

        /// <summary>
        ///     Name of the cipher primitive, e.g. AES.
        /// </summary>
        string CipherName { get; }

        /// <summary>
        ///     Size of the key being used, in bits.
        /// </summary>
        int KeySizeBits { get; }

        /// <summary>
        ///     Data that initialises the state of the cipher prior to processing any data.
        /// </summary>
        byte[] InitialisationVector { get; }

        /// <summary>
        ///     Name of the mode of operation for the cipher, where applicable (block ciphers).
        /// </summary>
        string ModeName { get; }

        /// <summary>
        ///     Size of each block of data in bits.
        /// </summary>
        int? BlockSizeBits { get; }

        /// <summary>
        ///     Name of a scheme for 'padding' blocks to full size, where applicable 
        ///     (block ciphers in some modes of operation).
        /// </summary>
        /// <seealso cref="ModeName"/>
        string PaddingName { get; }
    }
}
