#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;
using ObscurCore.Cryptography.Signing.Primitives;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Custom.Ed25519;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
    public static class Curve25519
    {
        public static readonly int PublicKeySizeInBytes = 32;
        public static readonly int PrivateKeySeedSizeInBytes = 32;
        public static readonly int SharedKeySizeInBytes = 32;

        /// <summary>
        ///     Creates a private key from an array of 32 random bytes.
        /// </summary>
        /// <param name="bytes">Seed entropy. Must be 32 bytes (256 bits) long.</param>
        /// <returns>Private key as bytes.</returns>
        public static byte[] CreatePrivateKey(byte[] bytes)
        {
            if (bytes == null) {
                throw new ArgumentNullException();
            }
            if (bytes.Length != PrivateKeySeedSizeInBytes) {
                throw new ArgumentException("Seed entropy must be 32 bytes (256 bits) in length.", "bytes");
            }
            var privateKey = new byte[PrivateKeySeedSizeInBytes];
            bytes.CopyBytes(0, privateKey, 0, PrivateKeySeedSizeInBytes);
            privateKey[0] &= 0xF8;
            privateKey[31] &= 0x7F;
            privateKey[31] |= 0x40;

            return privateKey;
        }

        /// <summary>
        ///     Creates a public key from a (pre-clamped) private key.
        /// </summary>
        /// <param name="privateKey">Existing private key. 32 bytes in length.</param>
        /// <returns>Public key as bytes.</returns>
        public static byte[] CreatePublicKey(byte[] privateKey)
        {
            if (privateKey == null) {
                throw new ArgumentNullException();
            }
            if (privateKey.Length != PrivateKeySeedSizeInBytes) {
                throw new ArgumentException("Private key must be 32 bytes (256-bit).", "privateKey");
            }

            var publicKey = new byte[SharedKeySizeInBytes];

            GroupElementP3 A;
            GroupOperations.ge_scalarmult_base(out A, publicKey, 0);
            FieldElement publicKeyFE;
            EdwardsToMontgomeryX(out publicKeyFE, ref A.Y, ref A.Z);
            FieldOperations.fe_tobytes(publicKey, 0, ref publicKeyFE);

            return publicKey;
        }

        public static byte[] CalculateSharedSecret(byte[] privKey, byte[] pubKey, bool naclCompat = false)
        {
            var key = new byte[SharedKeySizeInBytes];
            MontgomeryOperations.scalarmult(key, 0, privKey, 0, pubKey, 0);
            if (naclCompat)
                KeyExchangeOutputHashNaCl(key, 0);
            return key;
        }

        public static byte[] CalculateSharedSecret(ECKey privKey, ECKey pubKey, bool naclCompat = false)
        {
            if (pubKey.CurveName.Equals(DjbCurve.Ed25519.ToString())) {
                return Ed25519.KeyExchange(pubKey.EncodedKey, privKey.EncodedKey);
            }
            if (pubKey.CurveName.Equals(DjbCurve.Curve25519.ToString())) {

                return CalculateSharedSecret(privKey.EncodedKey, pubKey.EncodedKey, naclCompat);
            }
            throw new ArgumentException("Curve not compatible.");
        }

        private static readonly byte[] HSalsaNonceZeroes = new byte[16];

        internal static void KeyExchangeOutputHashNaCl(byte[] sharedKey, int offset)
        {
            XSalsa20Engine.HSalsa20(sharedKey, 0, sharedKey, HSalsaNonceZeroes);
        }

        internal static void EdwardsToMontgomeryX(out FieldElement montgomeryX, ref FieldElement edwardsY, ref FieldElement edwardsZ)
        {
            FieldElement tempX, tempZ;
            FieldOperations.fe_add(out tempX, ref edwardsZ, ref edwardsY);
            FieldOperations.fe_sub(out tempZ, ref edwardsZ, ref edwardsY);
            FieldOperations.fe_invert(out tempZ, ref tempZ);
            FieldOperations.fe_mul(out montgomeryX, ref tempX, ref tempZ);
        }
    }
}
