using System.Collections.Generic;
using System.Linq;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.DTO;
using ObscurCore.Cryptography.KeyAgreement;

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
			Alice.ForeignEcKeys = Bob.EcKeypairs.Select(keypair => keypair.ExportPublicKey());
			Bob.ForeignEcKeys = Alice.EcKeypairs.Select(keypair => keypair.ExportPublicKey());
        }
    }

    /// <summary>
    /// Implementation of key provider for tests. Generates random keys.
    /// </summary>
    public class KeyProvider : IKeyProvider
    {
		public KeyProvider(int keysToMake = 1) {
            var symKeys = new List<byte[]>();
			var ecKeypairs = new List<EcKeypair>();

            for (int i = 0; i < keysToMake; i++) {
                var newKey = new byte[16];
                StratCom.EntropySource.NextBytes(newKey);
                symKeys.Add(newKey);

                newKey = new byte[32];
                StratCom.EntropySource.NextBytes(newKey);
                var c25519PrivateKey = Curve25519.CreatePrivateKey(newKey);
                var c25519PublicKey = Curve25519.CreatePublicKey(c25519PrivateKey);
				var keypair = new EcKeypair {
					CurveProviderName = "DJB",
					CurveName = DjbCurve.Curve25519.ToString(),
					EncodedPublicKey = c25519PublicKey,
					EncodedPrivateKey = c25519PrivateKey
                };
				ecKeypairs.Add(keypair);
            }

            SymmetricKeys = symKeys;
			EcKeypairs = ecKeypairs;
        }

        /// <summary>
        /// Symmetric key(s) that the local user owns.
        /// </summary>
		public IEnumerable<byte[]> SymmetricKeys { get; set; }

        /// <summary>
        /// Elliptic curve key(s) that the local user owns.
        /// </summary>
		public IEnumerable<EcKeypair> EcKeypairs { get; set; }

        /// <summary>
        /// Elliptic curve public key(s) of foreign entities.
        /// </summary>
		public IEnumerable<EcKeyConfiguration> ForeignEcKeys { get; set; }
    }
}
