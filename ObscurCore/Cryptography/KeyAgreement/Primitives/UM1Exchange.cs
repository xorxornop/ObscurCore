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

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
	// One-Pass Unified Model, C(1,2 EC-DHC). Defined in NIST 800-56A in section 6.2.1.2.
	
	/// <summary>
	/// One-Pass Unified Model EC-DHC functionality for initiator/sender.
	/// </summary>
	/// <remarks>
	/// Establishes a key between two parties with EC public keys known to each other 
	/// using the One-Pass Unified Model, a derivative of Elliptic Curve Diffie-Hellman 
	/// with cofactor multiplication.
	/// <para>
	/// The EC keypairs that both participants have must share the same domain properties,
	/// curve, key length, etc. If using this over ObscurServ, query the service to get 
	/// definitive values. A user may have several public keys, corresponding to either 
	/// different PKC schemes, or incompatible instances (e.g domain parameters) thereof.
	/// However, a user is not allowed to have multiple keys of the same configuration.
	/// </para>
	/// </remarks>		
	public sealed class UM1ExchangeInitiator
	{
		private readonly ECPrivateKeyParameters d_static_U; // Private key of initiator (local user - sender)
		private readonly ECPublicKeyParameters Q_static_V; // Public key of responder (remote user - receiver)
		
		public UM1ExchangeInitiator (ECPublicKeyParameters responderPublic, ECPrivateKeyParameters initiatorPrivate) {
			this.Q_static_V = responderPublic;
			this.d_static_U = initiatorPrivate;
		}
		
		/// <summary>
		/// Calculates the shared secret in participant U's role.
		/// </summary>
		/// <param name='Q_key'>
		/// Public key of the initiator (U, sender).
		/// </param>
		/// <param name='Q_ephemeral_V'>
		/// Ephemeral public key to send to the responder (V, receiver).
		/// </param>
		public byte[] CalculateSharedSecret (out ECPublicKeyParameters Q_ephemeral_V) {
			AsymmetricCipherKeyPair pair = ECAgreementUtility.GenerateKeyPair(Q_static_V.Parameters);
			Q_ephemeral_V = (ECPublicKeyParameters)pair.Public;
			
			ECDomainParameters domain = Q_static_V.Parameters;

		    // Calculate shared static secret 'Zs'
			var Zs = ECAgreementUtility.CalculateDHCSecret(domain, Q_static_V, d_static_U); // EC-DHC
			byte[] Zs_encoded = Zs.GetEncoded();
			
			// Calculate shared ephemeral secret 'Ze'
			ECPrivateKeyParameters d_ephemeral_U = (ECPrivateKeyParameters) pair.Private;
			var Ze = ECAgreementUtility.CalculateDHCSecret(domain, Q_static_V, d_ephemeral_U); // EC-DHC
			byte[] Ze_encoded = Ze.GetEncoded();
			
			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
			Array.Copy(Ze_encoded, Z, Ze_encoded.Length);
			Array.Copy(Zs_encoded, 0, Z, Ze_encoded.Length, Zs_encoded.Length);
			return Z;
		}
	}
	
	/// <summary>
	/// One-Pass Unified Model EC-DHC functionality for responder/receiver.
	/// </summary>
	public sealed class UM1ExchangeResponder
	{
		private readonly ECPrivateKeyParameters d_static_V; // Private key of respondent (local user - receiver)
		private readonly ECPublicKeyParameters Q_static_U; // Public key of initiator (remote user - sender)
		
		public UM1ExchangeResponder (ECPublicKeyParameters senderPublic, ECPrivateKeyParameters responderPrivate) {
			this.Q_static_U = senderPublic;
			this.d_static_V = responderPrivate;
		}
		
		/// <summary>
		/// Calculates the shared secret in participant V's role.
		/// </summary>
		/// <param name='Q_ephemeral_U'>
		/// Ephemeral public key supplied by the initiator (U, sender).
		/// </param>
		public byte[] CalculateSharedSecret(ECPublicKeyParameters Q_ephemeral_U) {
			// TODO: Verify QeU! Section 5.6.2.3.
			
			ECDomainParameters domain = Q_static_U.Parameters;

		    // Calculate shared static secret 'Zs'
			var Zs = ECAgreementUtility.CalculateDHCSecret(domain, Q_static_U, d_static_V); // EC-DHC
			byte[] Zs_encoded = Zs.GetEncoded();
			
			// Calculate shared ephemeral secret 'Ze'
			var Ze = ECAgreementUtility.CalculateDHCSecret(domain, Q_ephemeral_U, d_static_V); // EC-DHC
			byte[] Ze_encoded = Ze.GetEncoded();
			
			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
			Array.Copy(Ze_encoded, Z, Ze_encoded.Length);
			Array.Copy(Zs_encoded, 0, Z, Ze_encoded.Length, Zs_encoded.Length);
			return Z;
		}
	}



}

