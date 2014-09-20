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
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Custom.Ed25519;

namespace ObscurCore.Cryptography.Signing.Primitives
{
    public static class Ed25519
    {
        public static readonly int PublicKeySizeInBytes = 32;
        public static readonly int SignatureSizeInBytes = 64;
        public static readonly int ExpandedPrivateKeySizeInBytes = 32 * 2;
        public static readonly int PrivateKeySeedSizeInBytes = 32;
        public static readonly int SharedKeySizeInBytes = 32;

        public static bool Verify(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> publicKey)
        {
            if (signature.Count != SignatureSizeInBytes) {
                throw new ArgumentException(string.Format("Signature size must be {0}", SignatureSizeInBytes), "signature.Count");
            }
            if (publicKey.Count != PublicKeySizeInBytes) {
                throw new ArgumentException(string.Format("Public key size must be {0}", PublicKeySizeInBytes), "publicKey.Count");
            }

            return Ed25519Operations.crypto_sign_verify(signature.Array, signature.Offset, message.Array, message.Offset, message.Count,
                publicKey.Array, publicKey.Offset);
        }

        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            if (signature == null) {
                throw new ArgumentNullException("signature");
            }
            if (message == null) {
                throw new ArgumentNullException("message");
            }
            if (publicKey == null) {
                throw new ArgumentNullException("publicKey");
            }
            if (signature.Length != SignatureSizeInBytes) {
                throw new ArgumentException(string.Format("Signature size must be {0}", SignatureSizeInBytes), "signature.Length");
            }
            if (publicKey.Length != PublicKeySizeInBytes) {
                throw new ArgumentException(string.Format("Public key size must be {0}", PublicKeySizeInBytes), "publicKey.Length");
            }
            return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, message.Length, publicKey, 0);
        }

        public static void Sign(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> expandedPrivateKey)
        {
            if (signature.Array == null) {
                throw new ArgumentNullException("signature.Array");
            }
            if (signature.Count != SignatureSizeInBytes) {
                throw new ArgumentException("signature.Count");
            }
            if (expandedPrivateKey.Array == null) {
                throw new ArgumentNullException("expandedPrivateKey.Array");
            }
            if (expandedPrivateKey.Count != ExpandedPrivateKeySizeInBytes) {
                throw new ArgumentException("expandedPrivateKey.Count");
            }
            if (message.Array == null) {
                throw new ArgumentNullException("message.Array");
            }
            Ed25519Operations.crypto_sign2(signature.Array, signature.Offset, message.Array, message.Offset, message.Count,
                expandedPrivateKey.Array, expandedPrivateKey.Offset);
        }

        public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)
        {
            var signature = new byte[SignatureSizeInBytes];
            Sign(new ArraySegment<byte>(signature), new ArraySegment<byte>(message), new ArraySegment<byte>(expandedPrivateKey));
            return signature;
        }

        public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
        {
            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            privateKey.SecureWipe();
            return publicKey;
        }

        public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
        {
            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            publicKey.SecureWipe();
            return privateKey;
        }

        public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)
        {
            if (privateKeySeed == null) {
                throw new ArgumentNullException("privateKeySeed");
            }
            if (privateKeySeed.Length != PrivateKeySeedSizeInBytes) {
                throw new ArgumentException("privateKeySeed");
            }
            var pk = new byte[PublicKeySizeInBytes];
            var sk = new byte[ExpandedPrivateKeySizeInBytes];
            Ed25519Operations.crypto_sign_keypair(pk, 0, sk, 0, privateKeySeed, 0);
            publicKey = pk;
            expandedPrivateKey = sk;
        }

        [Obsolete("Needs more testing")]
        public static void KeyPairFromSeed(ArraySegment<byte> publicKey, ArraySegment<byte> expandedPrivateKey,
                                           ArraySegment<byte> privateKeySeed)
        {
            if (publicKey.Array == null) {
                throw new ArgumentNullException("publicKey.Array");
            }
            if (expandedPrivateKey.Array == null) {
                throw new ArgumentNullException("expandedPrivateKey.Array");
            }
            if (privateKeySeed.Array == null) {
                throw new ArgumentNullException("privateKeySeed.Array");
            }
            if (publicKey.Count != PublicKeySizeInBytes) {
                throw new ArgumentException("publicKey.Count");
            }
            if (expandedPrivateKey.Count != ExpandedPrivateKeySizeInBytes) {
                throw new ArgumentException("expandedPrivateKey.Count");
            }
            if (privateKeySeed.Count != PrivateKeySeedSizeInBytes) {
                throw new ArgumentException("privateKeySeed.Count");
            }
            Ed25519Operations.crypto_sign_keypair(
                publicKey.Array, publicKey.Offset,
                expandedPrivateKey.Array, expandedPrivateKey.Offset,
                privateKeySeed.Array, privateKeySeed.Offset);
        }

        public static byte[] KeyExchange(byte[] publicKey, byte[] privateKey)
        {
            var sharedKey = new byte[SharedKeySizeInBytes];
            KeyExchange(new ArraySegment<byte>(sharedKey), new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
            return sharedKey;
        }

        public static void KeyExchange(ArraySegment<byte> sharedKey, ArraySegment<byte> publicKey, ArraySegment<byte> privateKey, bool naclCompat = false)
        {
            if (sharedKey.Array == null) {
                throw new ArgumentNullException("sharedKey.Array");
            }
            if (publicKey.Array == null) {
                throw new ArgumentNullException("publicKey.Array");
            }
            if (privateKey.Array == null) {
                throw new ArgumentNullException("privateKey");
            }
            if (sharedKey.Count != SharedKeySizeInBytes) {
                throw new ArgumentException("sharedKey.Count != 32");
            }
            if (publicKey.Count != PublicKeySizeInBytes) {
                throw new ArgumentException("publicKey.Count != 32");
            }
            if (privateKey.Count != ExpandedPrivateKeySizeInBytes) {
                throw new ArgumentException("privateKey.Count != 64");
            }

            FieldElement montgomeryX, edwardsY, edwardsZ, sharedMontgomeryX;
            FieldOperations.fe_frombytes(out edwardsY, publicKey.Array, publicKey.Offset);
            FieldOperations.fe_1(out edwardsZ);
            Curve25519.EdwardsToMontgomeryX(out montgomeryX, ref edwardsY, ref edwardsZ);

            IHash hasher = AuthenticatorFactory.CreateHashPrimitive(HashFunction.Sha512);
            hasher.BlockUpdate(privateKey.Array, privateKey.Offset, 32);
            byte[] h = new byte[64];
            hasher.DoFinal(h, 0);
            ScalarOperations.sc_clamp(h, 0);
            MontgomeryOperations.scalarmult(out sharedMontgomeryX, h, 0, ref montgomeryX);
            h.SecureWipe();
            FieldOperations.fe_tobytes(sharedKey.Array, sharedKey.Offset, ref sharedMontgomeryX);

            if (naclCompat)
                Curve25519.KeyExchangeOutputHashNaCl(sharedKey.Array, sharedKey.Offset);
        }
    }
}
