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

using System;
using ObscurCore.DTO;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.KeyAgreement.Primitives;

namespace ObscurCore.Cryptography.KeyAgreement
{
	public static class KeyAgreementFactory
	{
		/// <summary>
		/// Performs a Elliptic Curve Diffie-Hellman key agreement
		/// </summary>
		/// <returns>The ECDH shared secret.</returns>
		/// <param name="publicKey">Public key.</param>
		/// <param name="privateKey">Private key.</param>
		public static byte[] CalculateEcdhSecret (EcKeyConfiguration publicKey, EcKeyConfiguration privateKey) {
			if (publicKey.CurveName.Equals(DjbCurve.Curve25519.ToString())) {
				return Curve25519.CalculateSharedSecret (privateKey.EncodedKey, publicKey.EncodedKey);
			} else {
				return CalculateEcdhSecret (DecodeToPublicKey(publicKey), DecodeToPrivateKey(privateKey)).ToByteArrayUnsigned ();
			}
		}

		/// <summary>
		/// Performs a Elliptic Curve Diffie-Hellman key agreement with cofactor multiplication.
		/// </summary>
		/// <returns>The ECDHC shared secret.</returns>
		/// <param name="publicKey">Public key.</param>
		/// <param name="privateKey">Private key.</param>
		public static byte[] CalculateEcdhcSecret (EcKeyConfiguration publicKey, EcKeyConfiguration privateKey) {
			if (publicKey.CurveName.Equals(DjbCurve.Curve25519.ToString())) {
				return Curve25519.CalculateSharedSecret (privateKey.EncodedKey, publicKey.EncodedKey);
			} else {
				return CalculateEcdhcSecret (DecodeToPublicKey(publicKey), DecodeToPrivateKey(privateKey)).ToByteArrayUnsigned ();
			}
		}

		/// <summary>
		/// Calculates the shared secret in a Diffie-Hellman scheme.
		/// </summary>
		/// <param name="Q">Public component of an EC keypair.</param>
		/// <param name="d">Private component of an EC keypair.</param>
		public static BigInteger CalculateEcdhSecret (ECPublicKeyParameters Q, ECPrivateKeyParameters d) {
			var P = KeypairFactory.EcBasePointMultiplier.Multiply (Q.Q, d.D).Normalize();

			if (P.IsInfinity)
				throw new InvalidOperationException("Infinity is not a valid agreement value for ECDH");

			return P.AffineXCoord.ToBigInteger ();
		}

		/// <summary>
		/// Calculates the shared secret in a Diffie-Hellman scheme with cofactor multiplication.
		/// </summary>
		/// <param name="domain">Domain parameters for the public and private keys provided.</param>
		/// <param name="Q">Public component of an EC keypair.</param>
		/// <param name="d">Private component of an EC keypair.</param>
		public static BigInteger CalculateEcdhcSecret (ECPublicKeyParameters Q, ECPrivateKeyParameters d) {
			ECDomainParameters domain = Q.Parameters;
			BigInteger hd = domain.H.Multiply(d.D).Mod(domain.N);

			var P = KeypairFactory.EcBasePointMultiplier.Multiply (Q.Q, hd).Normalize();

			if (P.IsInfinity)
				throw new InvalidOperationException("Infinity is not a valid agreement value for ECDHC");

			return P.AffineXCoord.ToBigInteger();
		}

		internal static ECPublicKeyParameters DecodeToPublicKey (EcKeyConfiguration ecKey) {
			ECPublicKeyParameters publicKey;
			try {
				var domain = NamedEllipticCurves.GetEcCurveData(ecKey.CurveName).GetParameters ();
				var point = domain.Curve.DecodePoint(ecKey.EncodedKey);
				publicKey = new ECPublicKeyParameters("ECDHC", point, domain);
			} catch (NotSupportedException) {
				throw new NotSupportedException ("EC curve specified for UM1 agreement is not in the collection of curves of the provider.");
			} catch (Exception) {
				throw new ConfigurationInvalidException("Unspecified error occured in decoding EC key.");
			}
			return publicKey;
		}

		internal static ECPrivateKeyParameters DecodeToPrivateKey (EcKeyConfiguration ecKey) {
			ECPrivateKeyParameters privateKey;
			try {
				var domain = NamedEllipticCurves.GetEcCurveData(ecKey.CurveName).GetParameters ();
				privateKey = new ECPrivateKeyParameters("ECDHC", new BigInteger(ecKey.EncodedKey), domain);
			} catch (NotSupportedException) {
				throw new NotSupportedException ("EC curve specified for UM1 agreement is not in the collection of curves of the provider.");
			} catch (Exception) {
				throw new ConfigurationInvalidException("Unspecified error occured in decoding EC key.");
			}
			return privateKey;
		}
	}
}

