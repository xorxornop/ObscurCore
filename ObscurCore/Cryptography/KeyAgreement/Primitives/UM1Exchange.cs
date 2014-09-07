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
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
    /// <summary>
    ///     One-Pass Unified Model C(1,2 EC-DHC) key agreement protocol primitive.
    /// </summary>
    /// <remarks>
    ///     Defined in NIST 800-56A in section 6.2.1.2.
    ///     Establishes a key between two parties with EC public keys known to each other
    ///     using the One-Pass Unified Model, a derivative of Elliptic Curve Diffie-Hellman
    ///     with cofactor multiplication, but with the initiator also using an ephemeral
    ///     keypair for unilateral forward secrecy.
    /// </remarks>
    public static class Um1Exchange
    {
        /// <summary>
        ///     Calculate the shared secret in participant U's (initiator) role.
        /// </summary>
        /// <param name="recipientPublicKey">Public key of the recipient.</param>
        /// <param name="senderPrivateKey">Private key of the sender.</param>
        /// <param name="ephemeralSenderPublicKey">
        ///     Ephemeral public key to send to the responder (V, receiver). Output to this
        ///     parameter.
        /// </param>
        public static byte[] Initiate(ECKey recipientPublicKey, ECKey senderPrivateKey,
            out ECKey ephemeralSenderPublicKey)
        {
            if (recipientPublicKey.PublicComponent == false) {
                throw new ArgumentException("Recipient key is not public component.", "recipientPublicKey");
            }
            if (senderPrivateKey.PublicComponent) {
                throw new ArgumentException("Sender key not private component.", "senderPrivateKey");
            }

            ECKey Q_static_V = recipientPublicKey;
            ECKey d_static_U = senderPrivateKey;

            ECKeypair kp_ephemeral_U = KeypairFactory.GenerateEcKeypair(senderPrivateKey.CurveName);
            ECKey Q_ephemeral_U = kp_ephemeral_U.ExportPublicKey();
            ECKey d_ephemeral_U = kp_ephemeral_U.GetPrivateKey();

            // Calculate shared ephemeral secret 'Ze'
            byte[] Ze = KeyAgreementFactory.CalculateEcdhcSecret(Q_static_V, d_ephemeral_U);
            // Calculate shared static secret 'Zs'
            byte[] Zs = KeyAgreementFactory.CalculateEcdhcSecret(Q_static_V, d_static_U);

            // Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
            var Z = new byte[Ze.Length + Zs.Length];
            Ze.CopyBytes(0, Z, 0, Ze.Length);
            Zs.CopyBytes(0, Z, Ze.Length, Zs.Length);
            ephemeralSenderPublicKey = Q_ephemeral_U;

            // Zero intermediate secrets
            Ze.SecureWipe();
            Zs.SecureWipe();

            return Z;
        }

        public static byte[] Initiate(ECPublicKeyParameters recipientPublicKey, ECPrivateKeyParameters senderPrivateKey,
            out ECPublicKeyParameters ephemeralSenderPublicKey)
        {
            ECPublicKeyParameters Q_static_V = recipientPublicKey;
            ECPrivateKeyParameters d_static_U = senderPrivateKey;

            ECPoint QeV;
            BigInteger deU;
            KeypairFactory.GenerateEcKeypair(recipientPublicKey.Parameters, out QeV, out deU);

            var Q_ephemeral_V = new ECPublicKeyParameters("ECDHC", QeV, recipientPublicKey.Parameters);
            var d_ephemeral_U = new ECPrivateKeyParameters("ECDHC", deU, recipientPublicKey.Parameters);

            // Calculate shared ephemeral secret 'Ze'
            BigInteger Ze = KeyAgreementFactory.CalculateEcdhcSecret(Q_static_V, d_ephemeral_U); // EC-DHC
            byte[] Ze_encoded = Ze.ToByteArrayUnsigned();

            // Calculate shared static secret 'Zs'
            BigInteger Zs = KeyAgreementFactory.CalculateEcdhcSecret(Q_static_V, d_static_U); // EC-DHC
            byte[] Zs_encoded = Zs.ToByteArrayUnsigned();

            // Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
            var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
            Ze_encoded.CopyBytes(0, Z, 0, Ze_encoded.Length);
            Zs_encoded.CopyBytes(0, Z, Ze_encoded.Length, Zs_encoded.Length);
            ephemeralSenderPublicKey = Q_ephemeral_V;

            // Zero intermediate secrets
            Ze_encoded.SecureWipe();
            Zs_encoded.SecureWipe();

            return Z;
        }

        /// <summary>
        ///     Calculates the shared secret in participant V's (responder) role.
        /// </summary>
        /// <param name="senderPublicKey">Public key of the sender.</param>
        /// <param name="recipientPrivateKey">Private key of the receiver.</param>
        /// <param name='ephemeralSenderPublicKey'>Ephemeral public key supplied by the initiator (U, sender).</param>
        public static byte[] Respond(ECKey senderPublicKey, ECKey recipientPrivateKey,
            ECKey ephemeralSenderPublicKey)
        {
            if (senderPublicKey.PublicComponent == false) {
                throw new ArgumentException("Sender key is not public component.", "senderPublicKey");
            }
            if (recipientPrivateKey.PublicComponent) {
                throw new ArgumentException("Recipient key not private component.", "recipientPrivateKey");
            }
            if (ephemeralSenderPublicKey.PublicComponent == false) {
                throw new ArgumentException("Ephemeral sender key is not public component.", "ephemeralSenderPublicKey");
            }

            ECKey Q_static_U = senderPublicKey;
            ECKey d_static_V = recipientPrivateKey;
            ECKey Q_ephemeral_U = ephemeralSenderPublicKey;

            // Calculate shared ephemeral secret 'Ze'
            byte[] Ze = KeyAgreementFactory.CalculateEcdhcSecret(Q_ephemeral_U, d_static_V);
            // Calculate shared static secret 'Zs'
            byte[] Zs = KeyAgreementFactory.CalculateEcdhcSecret(Q_static_U, d_static_V);

            // Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
            var Z = new byte[Ze.Length + Zs.Length];
            Ze.CopyBytes(0, Z, 0, Ze.Length);
            Zs.CopyBytes(0, Z, Ze.Length, Zs.Length);

            // Zero intermediate secrets
            Ze.SecureWipe();
            Zs.SecureWipe();

            return Z;
        }

        public static byte[] Respond(ECPublicKeyParameters senderPublicKey, ECPrivateKeyParameters receiverPrivateKey,
            ECPublicKeyParameters ephemeralSenderPublicKey)
        {
            ECPublicKeyParameters Q_static_U = senderPublicKey;
            ECPrivateKeyParameters d_static_V = receiverPrivateKey;
            ECPublicKeyParameters Q_ephemeral_U = ephemeralSenderPublicKey;

            // Calculate shared ephemeral secret 'Ze'
            BigInteger Ze = KeyAgreementFactory.CalculateEcdhcSecret(Q_ephemeral_U, d_static_V); // EC-DHC
            byte[] Ze_encoded = Ze.ToByteArrayUnsigned();

            // Calculate shared static secret 'Zs'
            BigInteger Zs = KeyAgreementFactory.CalculateEcdhcSecret(Q_static_U, d_static_V); // EC-DHC
            byte[] Zs_encoded = Zs.ToByteArrayUnsigned();

            // Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
            var Z = new byte[Ze_encoded.Length + Zs_encoded.Length];
            Ze_encoded.CopyBytes(0, Z, 0, Ze_encoded.Length);
            Zs_encoded.CopyBytes(0, Z, Ze_encoded.Length, Zs_encoded.Length);

            // Zero intermediate secrets
            Ze_encoded.SecureWipe();
            Zs_encoded.SecureWipe();

            return Z;
        }
    }
}
