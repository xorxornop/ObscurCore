using System.Collections.Generic;
using System.Linq;
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

			var c25519ent = new byte[32];
			StratCom.EntropySource.NextBytes(c25519ent);
			var c25519PrivateKey = Curve25519.CreatePrivateKey(c25519ent);
			var c25519PublicKey = Curve25519.CreatePublicKey(c25519PrivateKey);
			var c25519keypair = new EcKeypair {
				CurveProviderName = "DJB",
				CurveName = DjbCurve.Curve25519.ToString(),
				EncodedPublicKey = c25519PublicKey,
				EncodedPrivateKey = c25519PrivateKey
			};
			ecKeypairs.Add(c25519keypair);

			var curves = other.EcKeypairs.Where ((keypair) => keypair.CurveProviderName.Equals ("DJB") == false);
			foreach (var item in curves) {
				var curveInfo = NamedEllipticCurves.Curves [item.CurveName];
				var kpRaw = ECAgreementUtility.GenerateKeyPair (curveInfo.GetParameters());
				var keypair = new EcKeypair {
					CurveProviderName = NamedEllipticCurves.GetProvider(curveInfo.Name),
					CurveName = curveInfo.Name,
					EncodedPublicKey = ((ECPublicKeyParameters)kpRaw.Public).Q.GetEncoded(),
					EncodedPrivateKey = ((ECPrivateKeyParameters)kpRaw.Private).D.ToByteArray()
				};
				ecKeypairs.Add(keypair);
			}

			EcKeypairs = ecKeypairs;
		}

		public KeyProvider(int keysToMake = 3) {
            var symKeys = new List<byte[]>();
			var ecKeypairs = new List<EcKeypair>();

            for (int i = 0; i < keysToMake; i++) {
                var newKey = new byte[16];
                StratCom.EntropySource.NextBytes(newKey);
                symKeys.Add(newKey);


				var curveInfo = NamedEllipticCurves.Curves.ElementAt (StratCom.EntropySource.Next (NamedEllipticCurves.Curves.Count));

				var kpRaw = ECAgreementUtility.GenerateKeyPair (curveInfo.Value.GetParameters());
				var keypair = new EcKeypair {
					CurveProviderName = NamedEllipticCurves.GetProvider(curveInfo.Key),
					CurveName = curveInfo.Key,
					EncodedPublicKey = ((ECPublicKeyParameters)kpRaw.Public).Q.GetEncoded(),
					EncodedPrivateKey = ((ECPrivateKeyParameters)kpRaw.Private).D.ToByteArray()
				};
				ecKeypairs.Add(keypair);
            }

			var c25519ent = new byte[32];
			StratCom.EntropySource.NextBytes(c25519ent);
			var c25519PrivateKey = Curve25519.CreatePrivateKey(c25519ent);
			var c25519PublicKey = Curve25519.CreatePublicKey(c25519PrivateKey);
			var c25519keypair = new EcKeypair {
				CurveProviderName = "DJB",
				CurveName = DjbCurve.Curve25519.ToString(),
				EncodedPublicKey = c25519PublicKey,
				EncodedPrivateKey = c25519PrivateKey
			};
			ecKeypairs.Add(c25519keypair);

//			var bpCurve = BrainpoolEllipticCurve.BrainpoolP512t1;
//
//
//			//Enum.GetNames(typeof(BrainpoolEllipticCurve))
//			NamedEllipticCurves.Curves.ElementAt (StratCom.EntropySource.Next (NamedEllipticCurves.Curves.Count));
//
//			var curveInfo = NamedEllipticCurves.Curves [bpCurve.ToString()];
//			var bpKpRaw = ECAgreementUtility.GenerateKeyPair (curveInfo.GetParameters());
//			var bpKeypair = new EcKeypair {
//				CurveProviderName = "Brainpool",
//				CurveName = bpCurve.ToString(),
//				EncodedPublicKey = ((ECPublicKeyParameters)bpKpRaw.Public).Q.GetEncoded(),
//				EncodedPrivateKey = ((ECPrivateKeyParameters)bpKpRaw.Private).D.ToByteArray()
//			};
//			ecKeypairs.Add(bpKeypair);
//
//			var secCurve = Sec2EllipticCurve.Secp256r1;
//			curveInfo = NamedEllipticCurves.Curves [secCurve.ToString()];
//			var secKpRaw = ECAgreementUtility.GenerateKeyPair (curveInfo.GetParameters());
//			var secKeypair = new EcKeypair {
//				CurveProviderName = "SEC",
//				CurveName = bpCurve.ToString(),
//				EncodedPublicKey = ((ECPublicKeyParameters)secKpRaw.Public).Q.GetEncoded(),
//				EncodedPrivateKey = ((ECPrivateKeyParameters)secKpRaw.Private).D.ToByteArray()
//			};
//			ecKeypairs.Add(secKeypair);

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
