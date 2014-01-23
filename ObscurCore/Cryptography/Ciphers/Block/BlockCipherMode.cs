//
//  Copyright 2014  Matthew Ducker
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

namespace ObscurCore.Cryptography.Ciphers.Block
{
    /// <summary>
    /// Symmetric block cipher modes able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum BlockCipherMode
    {
        None,

        /// <summary>
        /// Ciphertext Block Chaining. Must be used with padding scheme.
        /// </summary>
        Cbc,

        /// <summary>
        /// Counter (aka Segmented Integer Counter, SIC). Can write partial blocks.
        /// </summary>
        Ctr,

        /// <summary>
        /// Cipher Feedback. Can write partial blocks.
        /// </summary>
        Cfb,

        /// <summary>
        /// Output Feedback. Can write partial blocks.
        /// </summary>
        Ofb
    }
}