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
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Support.Math;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
    /// <summary>
	/// One-Pass Unified Model C(1,2 EC-DHC) key agreement protocol primitive.
	/// </summary>
	/// <remarks>
	/// Defined in NIST 800-56A in section 6.2.1.2. 
	/// Establishes a key between two parties with EC public keys known to each other 
	/// using the One-Pass Unified Model, a derivative of Elliptic Curve Diffie-Hellman 
	/// with cofactor multiplication, but with the initiator also using an ephemeral 
	/// keypair for unilateral forward secrecy.
	/// </remarks>
    public static class Um1Exchange
    {

		/// <summary>
		/// Calculate the shared secret in participant U's (initiator) role.
		/// </summary>
		/// <param name="receiverPublicKey">Public key of the recipient.</param>
		/// <param name="senderPrivateKey">Private key of the sender.</param>
		/// <param name="ephemeralSenderPublicKey">Ephemeral public key to send to the responder (V, receiver). Output to this variable.</param>
		public static byte[] Initiate(EcKeyConfiguration receiverPublicKey, EcKeyConfiguration senderPrivateKey, 
			out EcKeyConfiguration ephemeralSenderPublicKey)
		{
			if (receiverPublicKey.PublicComponent == false) {
				throw new ArgumentException ();
			} else if (senderPrivateKey.PublicComponent == true) {
				throw new ArgumentException ();
			}

			EcKeyConfiguration Q_ephemeral_U;
			byte[] Zs, Ze;

			var Q_static_V = receiverPublicKey;
			var d_static_U = senderPrivateKey;

			var kp_ephemeral_U = KeypairFactory.GenerateEcKeypair (senderPrivateKey.CurveName);
			Q_ephemeral_U = kp_ephemeral_U.ExportPublicKey ();
			var d_ephemeral_U = kp_ephemeral_U.GetPrivateKey ();

			// Calculate shared ephemeral secret 'Ze'
			Ze = KeyAgreementFactory.CalculateEcdhcSecret (Q_static_V, d_ephemeral_U); // EC-DHC
			// Calculate shared static secret 'Zs'
			Zs = KeyAgreementFactory.CalculateEcdhcSecret (Q_static_V, d_static_U); // EC-DHC

			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze.Length + Zs.Length];
			Ze.CopyBytes (0, Z, 0, Ze.Length);
			Zs.CopyBytes (0, Z, Ze.Length, Zs.Length);
			ephemeralSenderPublicKey = Q_ephemeral_U;

			// Zero intermediate secrets
			Ze.SecureWipe ();
			Zs.SecureWipe ();

			return Z;
		}

		public static byte[] Initiate(ECPublicKeyParameters receiverPublicKey, ECPrivateKeyParameters senderPrivateKey, 
			out ECPublicKeyParameters ephemeralSenderPublicKey)
		{
			var Q_static_V = receiverPublicKey;
			var d_static_U = senderPrivateKey;

			ECPoint QeV;
			BigInteger deU;
			KeypairFactory.GenerateEcKeypair (receiverPublicKey.Parameters, out QeV, out deU);

			ECPublicKeyParameters Q_ephemeral_V;
			ECPrivateKeyParameters d_ephemeral_U;
			Q_ephemeral_V = new ECPublicKeyParameters ("ECDHC", QeV, receiverPublicKey.Parameters);
			d_ephemeral_U = new ECPrivateKeyParameters ("ECDHC", deU, receiverPublicKey.Parameters);

			// Calculate shared ephemeral secret 'Ze'
			var Ze = KeyAgreementFactory.CalculateEcdhcSecret (Q_static_V, d_ephemeral_U); // EC-DHC
			byte[] Ze_encoded = Ze.ToByteArrayUnsigned();

			// Calculate shared static secret 'Zs'
			var Zs = KeyAgreementFactory.CalculateEcdhcSecret (Q_static_V, d_static_U); // EC-DHC
			byte[] Zs_encoded = Zs.ToByteArrayUnsigned();

			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
			Ze_encoded.CopyBytes (0, Z, 0, Ze_encoded.Length);
			Zs_encoded.CopyBytes (0, Z, Ze_encoded.Length, Zs_encoded.Length);
			ephemeralSenderPublicKey = Q_ephemeral_V;

			// Zero intermediate secrets
			Ze_encoded.SecureWipe ();
			Zs_encoded.SecureWipe ();

			return Z;
		}

		/// <summary>
		/// Calculates the shared secret in participant V's (responder) role.
		/// </summary>
		/// <param name="senderPublicKey">Public key of the sender.</param>
		/// <param name="receiverPrivateKey">Private key of the receiver.</param>
		/// <param name='ephemeralPublicKey'>Ephemeral public key supplied by the initiator (U, sender).</param>
		public static byte[] Respond(EcKeyConfiguration senderPublicKey, EcKeyConfiguration receiverPrivateKey, 
			EcKeyConfiguration ephemeralSenderPublicKey)
		{
			if (senderPublicKey.PublicComponent == false) {
				throw new ArgumentException ();
			} else if (receiverPrivateKey.PublicComponent == true) {
				throw new ArgumentException ();
			} else if (ephemeralSenderPublicKey.PublicComponent == false) {
				throw new ArgumentException ();
			}

			byte[] Zs, Ze;

			var Q_static_U = senderPublicKey;
			var d_static_V = receiverPrivateKey;
			var Q_ephemeral_U = ephemeralSenderPublicKey;

			// Calculate shared ephemeral secret 'Ze'
			Ze = KeyAgreementFactory.CalculateEcdhcSecret (Q_ephemeral_U, d_static_V); // EC-DHC
			// Calculate shared static secret 'Zs'
			Zs = KeyAgreementFactory.CalculateEcdhcSecret (Q_static_U, d_static_V); // EC-DHC

			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze.Length + Zs.Length];
			Ze.CopyBytes (0, Z, 0, Ze.Length);
			Zs.CopyBytes (0, Z, Ze.Length, Zs.Length);

			// Zero intermediate secrets
			Ze.SecureWipe ();
			Zs.SecureWipe ();

			return Z;
		}

		public static byte[] Respond (ECPublicKeyParameters senderPublicKey, ECPrivateKeyParameters receiverPrivateKey, 
			ECPublicKeyParameters ephemeralSenderPublicKey)
		{
			var Q_static_U = senderPublicKey;
			var d_static_V = receiverPrivateKey;
			ECPublicKeyParameters Q_ephemeral_U = ephemeralSenderPublicKey;

			// Calculate shared ephemeral secret 'Ze'
			var Ze = KeyAgreementFactory.CalculateEcdhcSecret(Q_ephemeral_U, d_static_V); // EC-DHC
			byte[] Ze_encoded = Ze.ToByteArrayUnsigned();

			// Calculate shared static secret 'Zs'
			var Zs = KeyAgreementFactory.CalculateEcdhcSecret(Q_static_U, d_static_V); // EC-DHC
			byte[] Zs_encoded = Zs.ToByteArrayUnsigned();

			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
			Array.Copy(Ze_encoded, Z, Ze_encoded.Length);
			Array.Copy(Zs_encoded, 0, Z, Ze_encoded.Length, Zs_encoded.Length);

			// Zero intermediate secrets
			Ze_encoded.SecureWipe ();
			Zs_encoded.SecureWipe ();

			return Z;
		}
    }
}
