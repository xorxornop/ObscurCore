﻿#region License

// 	Copyright 2013-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

#endregion

using System;
using Obscur.Core.Cryptography.Information;
using Obscur.Core.Cryptography.Information.EllipticCurve;
using Obscur.Core.Cryptography.KeyAgreement.Primitives;
using Obscur.Core.Cryptography.Signing.Primitives;
using Obscur.Core.Cryptography.Support;
using Obscur.Core.Cryptography.Support.Math;
using Obscur.Core.Cryptography.Support.Math.EllipticCurve;
using Obscur.Core.DTO;

namespace Obscur.Core.Cryptography.KeyAgreement
{
    public static class KeyAgreementFactory
    {
        /// <summary>
        ///     Performs an Elliptic Curve Diffie-Hellman (ECDH) key agreement operation (scalar multiplication).
        /// </summary>
        /// <returns>The ECDH shared secret.</returns>
        /// <param name="publicKey">Public key.</param>
        /// <param name="privateKey">Private key.</param>
        public static byte[] CalculateEcdhSecret(ECKey publicKey, ECKey privateKey)
        {
            if (publicKey.CurveName.Equals(DjbCurve.Curve25519.ToString())) {
                return Curve25519.CalculateSharedSecret(privateKey.EncodedKey, publicKey.EncodedKey);
            } else if (publicKey.CurveName.Equals(DjbCurve.Ed25519.ToString())) {
                return Ed25519.KeyExchange(publicKey.EncodedKey, privateKey.EncodedKey);
            }
            return
                CalculateEcdhSecret(DecodeToPublicKey(publicKey), DecodeToPrivateKey(privateKey)).ToByteArrayUnsigned();
        }

        /// <summary>
        ///     Performs an Elliptic Curve Diffie-Hellman key agreement operation (scalar multiplication), 
        ///     with cofactor multiplication (ECDHC).
        /// </summary>
        /// <returns>The ECDHC shared secret.</returns>
        /// <param name="publicKey">Public key.</param>
        /// <param name="privateKey">Private key.</param>
        public static byte[] CalculateEcdhcSecret(ECKey publicKey, ECKey privateKey)
        {
            if (publicKey.CurveName.Equals(DjbCurve.Curve25519.ToString())) {
                return Curve25519.CalculateSharedSecret(privateKey.EncodedKey, publicKey.EncodedKey);
            } else if (publicKey.CurveName.Equals(DjbCurve.Ed25519.ToString())) {
                return Ed25519.KeyExchange(publicKey.EncodedKey, privateKey.EncodedKey);
            }
            return
                CalculateEcdhcSecret(DecodeToPublicKey(publicKey), DecodeToPrivateKey(privateKey)).ToByteArrayUnsigned();
        }

        /// <summary>
        ///     Performs an Elliptic Curve Diffie-Hellman (ECDH) key agreement operation (scalar multiplication).
        /// </summary>
        /// <param name="Q">Public component of an EC keypair.</param>
        /// <param name="d">Private component of an EC keypair.</param>
        public static BigInteger CalculateEcdhSecret(ECPublicKeyParameters Q, ECPrivateKeyParameters d)
        {
            ECPoint P = KeypairFactory.EcBasePointMultiplier.Multiply(Q.Q, d.D).Normalize();

            if (P.IsInfinity) {
                throw new InvalidOperationException("Infinity is not a valid agreement value for ECDH");
            }

            return P.AffineXCoord.ToBigInteger();
        }

        /// <summary>
        ///     Performs an Elliptic Curve Diffie-Hellman key agreement operation (scalar multiplication), 
        ///     with cofactor multiplication (ECDHC).
        /// </summary>
        /// <param name="Q">Public component of an EC keypair.</param>
        /// <param name="d">Private component of an EC keypair.</param>
        public static BigInteger CalculateEcdhcSecret(ECPublicKeyParameters Q, ECPrivateKeyParameters d)
        {
            ECDomainParameters domain = Q.Parameters;
            BigInteger hd = domain.H.Multiply(d.D).Mod(domain.N);

            ECPoint P = KeypairFactory.EcBasePointMultiplier.Multiply(Q.Q, hd).Normalize();

            if (P.IsInfinity) {
                throw new InvalidOperationException("Infinity is not a valid agreement value for ECDHC");
            }

            return P.AffineXCoord.ToBigInteger();
        }

        internal static ECPublicKeyParameters DecodeToPublicKey(ECKey ecKey)
        {
            ECPublicKeyParameters publicKey;
            try {
                ECDomainParameters domain = EcInformationStore.GetECCurveData(ecKey.CurveName).GetParameters();
                ECPoint point = domain.Curve.DecodePoint(ecKey.EncodedKey);
                publicKey = new ECPublicKeyParameters("ECDHC", point, domain);
            } catch (NotSupportedException) {
                throw new NotSupportedException(
                    "EC curve specified is not in the collection of curves of the provider.");
            } catch (Exception) {
                throw new ConfigurationInvalidException("Unspecified error occured in decoding EC key.");
            }
            return publicKey;
        }

        internal static ECPrivateKeyParameters DecodeToPrivateKey(ECKey ecKey)
        {
            ECPrivateKeyParameters privateKey;
            try {
                ECDomainParameters domain = EcInformationStore.GetECCurveData(ecKey.CurveName).GetParameters();
                privateKey = new ECPrivateKeyParameters("ECDHC", new BigInteger(ecKey.EncodedKey), domain);
            } catch (NotSupportedException) {
                throw new NotSupportedException(
                    "EC curve specified is not in the collection of curves of the provider.");
            } catch (Exception) {
                throw new ConfigurationInvalidException("Unspecified error occured in decoding EC key.");
            }
            return privateKey;
        }
    }
}
