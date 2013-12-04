using System;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
    public static class Curve25519UM1Exchange
    {
        /// <summary>
        /// Calculate the shared secret in participant U's (initiator) role.
        /// </summary>
        /// <param name="pubKeyReceiver">Public key of the recipient.</param>
        /// <param name="privKeySender">Private key of the sender.</param>
        /// <param name="Q_ephemeral_V">Ephemeral public key to send to the responder (V, receiver). Output to this variable.</param>
        /// <returns></returns>
        public static byte[] Initiate(byte[] pubKeyReceiver, byte[] privKeySender, out byte[] Q_ephemeral_V) {
            var privKeyEntropy = new byte[32];
            StratCom.EntropySource.NextBytes(privKeyEntropy);
            var ephPriv = Curve25519.CreatePrivateKey(privKeyEntropy);
            Q_ephemeral_V = Curve25519.CreatePublicKey(ephPriv);

            // Calculate shared static secret 'Zs'
            var Zs = Curve25519.CalculateSharedSecret(privKeySender, pubKeyReceiver);

            // Calculate shared ephemeral secret 'Ze'
            var Ze = Curve25519.CalculateSharedSecret(ephPriv, pubKeyReceiver);

            // Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze.Length + Zs.Length];
			Array.Copy(Ze, Z, Ze.Length);
			Array.Copy(Zs, 0, Z, Ze.Length, Zs.Length);
			return Z;
        }

        /// <summary>
        /// Calculate the shared secret in participant V's role.
        /// </summary>
        /// <param name="pubKeySender"></param>
        /// <param name="privKeyReceiver"></param>
        /// <param name="Q_ephemeral_U">Ephemeral public key supplied by the initiator (U, sender).</param>
        /// <returns></returns>
        public static byte[] Respond(byte[] pubKeySender, byte[] privKeyReceiver, byte[] Q_ephemeral_U) {
            // Calculate shared static secret 'Zs'
            var Zs = Curve25519.CalculateSharedSecret(privKeyReceiver, pubKeySender);

            // Calculate shared ephemeral secret 'Ze'
            var Ze = Curve25519.CalculateSharedSecret(privKeyReceiver, Q_ephemeral_U);

            // Concatenate Ze and Zs byte strings to form shared secret, pre-KDF : Ze||Zs
			var Z = new byte[Ze.Length + Zs.Length];
			Array.Copy(Ze, Z, Ze.Length);
			Array.Copy(Zs, 0, Z, Ze.Length, Zs.Length);
			return Z;
        }
    }
}
