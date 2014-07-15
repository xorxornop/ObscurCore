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

namespace ObscurCore.Cryptography.Ciphers.Information
{
    public sealed class BlockCipherInformation : CipherInformation
    {
        /// <summary>
        /// Array of allowable sizes (in bits) for the block size of the cipher.
        /// </summary>
        public int[] AllowableBlockSizes { get; internal set; }

        /// <summary>
        /// If no block size size is supplied when configuring the cipher, this is the size that should be used.
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
    }
}
