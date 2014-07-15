using System.Collections.Generic;
using System.Linq;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.DTO;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Information;
using ObscurCore.Cryptography.Support;
using System;

namespace ObscurCore.Tests.Cryptography
{
    public static class KeyProviders
    {
        public static KeyProvider Alice;
        public static KeyProvider Bob;

        static KeyProviders() {
            Alice = new KeyProvider();
			Bob = new KeyProvider(Alice);
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
		public KeyProvider (KeyProvider other)
		{
			SymmetricKeys = other.SymmetricKeys.Reverse().ToList();

			var ecKeypairs = new List<EcKeypair>();
			foreach (var item in other.EcKeypairs) {
				ecKeypairs.Add(KeypairFactory.GenerateEcKeypair(item.CurveName));
			}

			EcKeypairs = ecKeypairs;
		}

		public KeyProvider(int keysToMake = 5) {
            var symKeys = new List<byte[]>();
			var ecKeypairs = new List<EcKeypair>();

            for (int i = 0; i < keysToMake; i++) {
                var newKey = new byte[16];
                StratCom.EntropySupplier.NextBytes(newKey);
                symKeys.Add(newKey);

				var curveName = Athena.Cryptography.Curves.Keys.ElementAt(StratCom.EntropySupplier.Next(Athena.Cryptography.Curves.Count));
				ecKeypairs.Add(KeypairFactory.GenerateEcKeypair(curveName));
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
