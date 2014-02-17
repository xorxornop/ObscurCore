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
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Multiplier;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;

namespace ObscurCore.Cryptography.KeyAgreement
{
	public static class KeypairFactory
	{
		internal static ECMultiplier EcBasePointMultiplier = new FixedPointCombMultiplier ();

		public static EcKeypair GenerateEcKeypair (string curveName) {
			EcKeypair keypair;

			if (curveName.Equals ("Curve25519")) {
				var privEntropy = new byte[32];
				StratCom.EntropySupplier.NextBytes(privEntropy);
				var privateKey = Curve25519.CreatePrivateKey(privEntropy);
				var publicKey = Curve25519.CreatePublicKey(privateKey);

				keypair = new EcKeypair {
					CurveProviderName = "DJB",
					CurveName = DjbCurve.Curve25519.ToString (),
					EncodedPublicKey = publicKey,
					EncodedPrivateKey = privateKey
				};
			} else {
				ECPoint Q;
				BigInteger d;
				GenerateEcKeypair (curveName, out Q, out d);

				keypair = new EcKeypair {
					CurveProviderName = NamedEllipticCurves.GetProvider (curveName),
					CurveName = curveName,
					EncodedPublicKey = Q.GetEncoded (),
					EncodedPrivateKey = d.ToByteArray ()
				};
			}

			return keypair;
		}

		internal static void GenerateEcKeypair (string curveName, out ECPoint Q, out BigInteger d) {
			var domain = NamedEllipticCurves.Curves [curveName].GetParameters ();
			GenerateEcKeypair (domain, out Q, out d);
		}

		internal static void GenerateEcKeypair (ECDomainParameters domain, out ECPoint Q, out BigInteger d) {
			ECPoint g = domain.G;
			BigInteger n = domain.N;

			do {
				d = new BigInteger(n.BitLength, StratCom.EntropySupplier);
			} while (d.SignValue == 0 || (d.CompareTo(n) >= 0));

			Q = EcBasePointMultiplier.Multiply(domain.G, d);
		}
	}
}
