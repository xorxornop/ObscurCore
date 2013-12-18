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
    public static class UM1Exchange
    {
        /// <summary>
        /// Calculate the shared secret in participant U's (initiator) role.
        /// </summary>
        /// <param name="receiverPublicKey">Public key of the recipient.</param>
        /// <param name="senderPrivateKey">Private key of the sender.</param>
        /// <param name="ephemeralSenderPublicKey">Ephemeral public key to send to the responder (V, receiver). Output to this variable.</param>
        /// <returns></returns>
        public static byte[] Initiate(ECPublicKeyParameters receiverPublicKey, ECPrivateKeyParameters senderPrivateKey, 
            out ECPublicKeyParameters ephemeralSenderPublicKey)
        {
            var QsV = receiverPublicKey;
            var dsU = senderPrivateKey;
            ECPublicKeyParameters QeV;

            AsymmetricCipherKeyPair pair = ECAgreementUtility.GenerateKeyPair(QsV.Parameters);
			QeV = (ECPublicKeyParameters)pair.Public;
			
			ECDomainParameters domain = QsV.Parameters;

		    // Calculate shared static secret 'Zs'
			var Zs = ECAgreementUtility.CalculateDhcSecret(domain, QsV, dsU); // EC-DHC
			byte[] Zs_encoded = Zs.ToByteArrayUnsigned();
			
			// Calculate shared ephemeral secret 'Ze'
			ECPrivateKeyParameters deU = (ECPrivateKeyParameters) pair.Private;
			var Ze = ECAgreementUtility.CalculateDhcSecret(domain, QsV, deU); // EC-DHC
			byte[] Ze_encoded = Ze.ToByteArrayUnsigned();
			
			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
			Buffer.BlockCopy(Ze_encoded, 0, Z, 0, Ze_encoded.Length);
			Buffer.BlockCopy(Zs_encoded, 0, Z, Ze_encoded.Length, Zs_encoded.Length);
            ephemeralSenderPublicKey = QeV;
			return Z;
        }

        /// <summary>
		/// Calculates the shared secret in participant V's (responder) role.
		/// </summary>
		/// <param name="senderPublicKey">Public key of the sender.</param>
        /// <param name="receiverPrivateKey">Private key of the receiver.</param>
		/// <param name='ephemeralPublicKey'>Ephemeral public key supplied by the initiator (U, sender).</param>
        public static byte[] Respond(ECPublicKeyParameters senderPublicKey, ECPrivateKeyParameters receiverPrivateKey, 
            ECPublicKeyParameters ephemeralSenderPublicKey)
        {
            var QsU = senderPublicKey;
            var dsV = receiverPrivateKey;
            ECPublicKeyParameters QeU = ephemeralSenderPublicKey;
			ECDomainParameters domain = QsU.Parameters;
            // TODO: Verify QeU! Section 5.6.2.3.

		    // Calculate shared static secret 'Zs'
			var Zs = ECAgreementUtility.CalculateDhcSecret(domain, QsU, dsV); // EC-DHC
			byte[] Zs_encoded = Zs.ToByteArrayUnsigned();
			
			// Calculate shared ephemeral secret 'Ze'
			var Ze = ECAgreementUtility.CalculateDhcSecret(domain, QeU, dsV); // EC-DHC
			byte[] Ze_encoded = Ze.ToByteArrayUnsigned();
			
			// Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
			Array.Copy(Ze_encoded, Z, Ze_encoded.Length);
			Array.Copy(Zs_encoded, 0, Z, Ze_encoded.Length, Zs_encoded.Length);
			return Z;
        }

    }
}

