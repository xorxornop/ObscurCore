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

namespace ObscurCore.Cryptography.Ciphers.Stream
{
    /// <summary>
    /// Symmetric stream ciphers able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum SymmetricStreamCipher
    {
        None,

        /// <summary>
		/// Stream cipher designed for fast operation in software. 
		/// Simplified version of <seealso cref="Hc256"/>. 
		/// eSTREAM Phase 3 finalist.
        /// </summary>
        Hc128,

        /// <summary>
		/// Stream cipher designed for fast operation in software.
        /// </summary>
        Hc256,

        /// <summary>
		/// Software-optimised stream cipher. 
        /// eSTREAM Phase 3 candidate. Patented, but free for non-commercial use.
        /// </summary>
        Rabbit,
#if INCLUDE_RC4
    /// <summary>
    /// 40-to-2048-bit adjustible-length key stream cipher, used most famously in SSL and WEP encryption.
    /// </summary>
		Rc4,
#endif
		/// <summary>
		/// Stream cipher by Daniel J. Bernstein. eSTREAM Phase 3 candidate.
        /// </summary>
        Salsa20,

		/// <summary>
		/// Stream cipher by Daniel J. Bernstein. Modified version of <seealso cref="Salsa20"/>.
		/// </summary>
		ChaCha,

		/// <summary>
		/// Stream cipher by Daniel J. Bernstein. Improved version of <seealso cref="Salsa20"/>.
		/// </summary>
		XSalsa20,

        /// <summary>
		/// Stream cipher designed for high performance and efficient use in software. 
        /// eSTREAM Phase 3 candidate.
        /// </summary>
        Sosemanuk
    }
}