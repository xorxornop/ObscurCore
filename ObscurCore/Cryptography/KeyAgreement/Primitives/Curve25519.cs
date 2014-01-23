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

using System;
using ObscurCore.Cryptography.Authentication.Primitives;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
    public static class Curve25519
    {
        

        /// <summary>
		/// Creates a private key from an array of 32 random bytes.
        /// </summary>
        /// <param name="bytes">Source entropy. Must be 32 bytes (256 bits) long.</param>
        /// <returns>Private key as bytes.</returns>
        public static byte[] CreatePrivateKey(byte[] bytes) {
			if (bytes == null) throw new ArgumentNullException();
			if (bytes.Length != 32) throw new ArgumentException();
			var privateKey = new byte[32];
			Buffer.BlockCopy(bytes, 0, privateKey, 0, 32);
			privateKey[0] &= 0xF8;
			privateKey[31] &= 0x7F;
			privateKey[31] |= 0x40;
			return privateKey;
        }

        /// <summary>
        /// Creates a public key from a private key.
        /// </summary>
        /// <param name="privateKey">Existing private key. 32 bytes in length.</param>
        /// <returns>Public key as bytes.</returns>
		public static byte[] CreatePublicKey(byte[] privateKey) {
			if (privateKey == null) throw new ArgumentNullException();
			if (privateKey.Length != 32) throw new ArgumentException();
			// Use a different primitive depending on whether unsafe code is allowed
			#if INCLUDE_UNSAFE
			var publicKey = new byte[32];
			byte[] BaseP = new byte[32] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			unsafe {
				fixed (byte* q = publicKey, n = privateKey, p = BaseP) {
					Curve25519Donna.curve25519_donna(q, n, p);
				}
			}
			return publicKey;
			#else
			return Curve25519HansWolff.GetPublicKey(privateKey);
			#endif
        }

        public static byte[] CalculateSharedSecret(byte[] privKey, byte[] pubKey) {
			// Use a different primitive depending on whether unsafe code is allowed
			#if INCLUDE_UNSAFE
			var ss = new byte[32];
			unsafe {
				fixed (byte* q = ss, n = privKey, p = pubKey) {
					Curve25519Donna.curve25519_donna(q, n, p);
				}
			}
			return ss;
			#else
			//return Curve25519HansWolff.GetSharedSecret(privKey, pubKey);

			return MontgomeryCurve25519.KeyExchange(pubKey, privKey); // TODO: CHANGE!

			#endif
        }
	}   
}
