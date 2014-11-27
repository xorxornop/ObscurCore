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

namespace Obscur.Core.Cryptography.Ciphers.Block
{
    /// <summary>
    /// Symmetric block ciphers able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum BlockCipher
    {
        None,
        /// <summary>
        /// Very popular and well-regarded 128-bit block cipher, 128/192/256-bit key. 
        /// Restricted subset of Rijndael (which offers 128/192/256 block sizes).
        /// </summary>
        Aes,

        /// <summary>
        /// Classic block cipher. Published 1993 by Bruce Schneier.
        /// </summary>
        Blowfish,

        /// <summary>
        /// 128-bit block cipher jointly developed by Mitsubishi and NTT. Comparable to AES.
        /// </summary>
        Camellia,
#if INCLUDE_IDEA
        /// <summary>
        /// International Data SymmetricCipher Algorithm - patent unencumbered as of 2012. 64 bit block size.
        /// </summary>
        Idea,
#endif
        /// <summary>
        /// 128-bit block cipher. Year 2000 NESSIE entrant - not selected. Similar to AES.
        /// </summary>
        Noekeon,

        /// <summary>
        /// 128-bit block cipher. Finalist of AES content. Derivative of RC5.
        /// </summary>
        Rc6,

        /// <summary>
        /// 128-bit block cipher, finalist in AES content, 2nd place after Rijndael.
        /// </summary>
        Serpent,

        /// <summary>
        /// High performance large-block cipher. Successor to Twofish.
        /// </summary>
		Threefish,

        /// <summary>
        /// 128-bit block cipher. Derivative of Blowfish with better security.
        /// </summary>
        Twofish
    }
}