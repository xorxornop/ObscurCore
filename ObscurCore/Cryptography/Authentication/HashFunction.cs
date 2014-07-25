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

namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    ///     Hash/digest functions able to be used in a <see cref="HashStream" /> or as a <see cref="IDigest"/>.
    /// </summary>
    public enum HashFunction
    {
        None,

        /// <summary>
        ///     64-bit platform and software optimised, fast.
        ///     Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B256,

        /// <summary>
        ///     64-bit platform and software optimised, fast.
        ///     Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B384,

        /// <summary>
        ///     64-bit platform and software optimised, fast.
        ///     Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B512,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        /// </summary>
        Keccak224,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        /// </summary>
        Keccak256,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        /// </summary>
        Keccak384,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        /// </summary>
        Keccak512,

        /// <summary>
        ///     RACE Integrity Primitives Evaluation Message Digest. Output sice of 160 bits. Popular cipher
        ///     published in 1996. Designed in the open academic community, as opposed to the NSA-designed
        ///     SHA-1 of the similar time period.
        /// </summary>
        Ripemd160,
#if INCLUDE_SHA1
        /// <summary>
        ///     Very well known hash function/digest, but getting a little "long in the tooth" (old).
        ///     Output size is 160 bits (20 bytes).
        /// </summary>
        Sha1,
#endif

        /// <summary>
        ///     256-bit version of the SHA-2 hash family.
        /// </summary>
        Sha256,

        /// <summary>
        ///     512-bit version of the SHA-2 hash family.
        /// </summary>
        Sha512,

        /// <summary>
        ///     Output size of 192 bits.
        /// </summary>
        Tiger,

        Whirlpool
    }
}
