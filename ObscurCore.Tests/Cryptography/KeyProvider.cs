using System.Collections.Generic;
using System.Linq;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography
{
    public static class KeyProviders
    {
        public static KeyProvider Alice;
        public static KeyProvider Bob;

        static KeyProviders() {
            Alice = new KeyProvider();
            Bob = new KeyProvider();
            // Assign each other's public keys as foreign key sources
            Alice.ForeignCurve25519Keys = Bob.Curve25519Keypairs.Select(keypair => keypair.Public);
            Bob.ForeignCurve25519Keys = Alice.Curve25519Keypairs.Select(keypair => keypair.Public);
        }
    }


    /// <summary>
    /// Implementation of key provider for tests. Generates random keys.
    /// </summary>
    public class KeyProvider : IKeyProvider
    {
        public KeyProvider(int keysToMake = 5) {
            var symKeys = new List<byte[]>();
            var c25519Keypairs = new List<Curve25519Keypair>();

            for (int i = 0; i < keysToMake; i++) {
                var newKey = new byte[16];
                StratCom.EntropySource.NextBytes(newKey);
                symKeys.Add(newKey);

                newKey = new byte[32];
                StratCom.EntropySource.NextBytes(newKey);
                var c25519PrivateKey = Curve25519.CreatePrivateKey(newKey);
                var c25519PublicKey = Curve25519.CreatePublicKey(c25519PrivateKey);
                var keypair = new Curve25519Keypair
                    {
                        Public = c25519PublicKey,
                        Private = c25519PrivateKey
                    };
                c25519Keypairs.Add(keypair);
            }

            SymmetricKeys = symKeys;
            Curve25519Keypairs = c25519Keypairs;
        }

        /// <summary>
        /// Symmetric key(s) that the local user owns.
        /// </summary>
        public IEnumerable<byte[]> SymmetricKeys { get; private set; }

        /// <summary>
        /// Elliptic curve key(s) that the local user owns.
        /// </summary>
        public IEnumerable<EcKeypair> EcKeypairs { get; private set; }

        /// <summary>
        /// Elliptic curve public key(s) of foreign entities.
        /// </summary>
        public IEnumerable<EcKeyConfiguration> ForeignEcKeys { get; private set; }

        /// <summary>
        /// Curve25519 keypairs that the local user owns.
        /// </summary>
        public IEnumerable<Curve25519Keypair> Curve25519Keypairs { get; private set; }

        /// <summary>
        /// Curve25519 public key(s) of foreign entities.
        /// </summary>
        public IEnumerable<byte[]> ForeignCurve25519Keys { get; internal set; }
    }
}
