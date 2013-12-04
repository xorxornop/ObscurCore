//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using System.Collections.Generic;

namespace ObscurCore.Information
{
    public sealed class SymmetricCipherDescription
    {
        /// <summary>
        /// Name of the cryptographic cipher transform (must be a member of SymmetricBlockCiphers or SymmetricStreamCiphers).
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        /// Name to show a user or for a detailed specification.
        /// </summary>
        public string DisplayName { get; internal set; }

        /// <summary>
        /// Array of allowable sizes (in bits) for the block size of the cipher, where applicable. Set to -1 if stream cipher.
        /// </summary>
        public int[] AllowableBlockSizes { get; internal set; }

        /// <summary>
        /// If no block size size is supplied when configuring the cipher, this is the size that should be used, where applicable. Set to -1 if stream cipher.
        /// </summary>
        public int DefaultBlockSize { get; internal set; }

        /// <summary>
        /// Array of allowable sizes (in bits) for the cipher initialisation vector (IV).
        /// </summary>
        public int[] AllowableIvSizes { get; internal set; }

        /// <summary>
        /// If no IV size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultIvSize { get; internal set; }

        /// <summary>
        /// Array of allowable sizes (in bits) for the cryptographic key.
        /// </summary>
        public int[] AllowableKeySizes { get; internal set; }

        /// <summary>
        /// If no key size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultKeySize { get; internal set; }
    }
}