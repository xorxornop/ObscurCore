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
    ///     Message Authentication Code (MAC) functions able to be used in a <see cref="MacStream" />
    ///     or as a <see cref="IMac" />.
    /// </summary>
    public enum MacFunction
    {
        /// <summary>
        ///     64-bit platform & software optimised, fast. Supports additional salt and tag inputs.
        ///     Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B256,

        /// <summary>
        ///     64-bit platform & software optimised, fast. Supports additional salt and tag inputs.
        ///     Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B384,

        /// <summary>
        ///     64-bit platform & software optimised, fast. Supports additional salt and tag inputs.
        ///     Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B512,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        ///     Supports additional salt parameter.
        /// </summary>
        Keccak224,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        ///     Supports additional salt parameter.
        /// </summary>
        Keccak256,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        ///     Supports additional salt parameter.
        /// </summary>
        Keccak384,

        /// <summary>
        ///     Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction.
        ///     Supports additional salt parameter.
        /// </summary>
        Keccak512,

        Poly1305,

//		SipHash,

        /// <summary>
        ///     Also called OMAC1.
        ///     As the name suggests, uses a (configurable) symmetric block cipher as the core of the primitive.
        /// </summary>
        Cmac,

        /// <summary>
        ///     Hash-based MAC.
        ///     As the name suggests, uses a (configurable) hash function as the core of the primitive.
        /// </summary>
        Hmac
    }
}
