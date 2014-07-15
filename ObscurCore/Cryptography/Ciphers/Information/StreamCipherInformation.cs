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
    public sealed class StreamCipherInformation : CipherInformation
    {
        /// <summary>
        /// Array of allowable sizes (in bits) for the cipher nonce.
        /// </summary>
        public int[] AllowableNonceSizes { get; internal set; }

        /// <summary>
        /// If no nonce size is supplied when configuring the cipher, 
        /// this is the size that should be used.
        /// </summary>
        public int DefaultNonceSize { get; internal set; }
    }
}
