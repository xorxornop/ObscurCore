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
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Support;

namespace ObscurCore.Cryptography.KeyAgreement.Information
{
	public abstract class EcNamedCurveInformation
	{
		/// <summary>
		/// Name of the elliptic curve.
		/// </summary>
		public string Name { get; protected internal set; }

		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
		public string DisplayName { get; protected internal set; }

		public int BitLength { get; protected internal set; }

		public abstract ECDomainParameters GetParameters();

		protected static BigInteger FromHex (string hex) {
			return new BigInteger(1, Hex.Decode(hex));
		}
	}

	/// <summary>
	/// Information for a named elliptic curve over Fp.
	/// </summary>
	public class FpEcNamedCurveInformation : EcNamedCurveInformation
	{
		public string Q { get; protected internal set; }
		public string A { get; protected internal set; }
		public string B { get; protected internal set; }
		public string G { get; protected internal set; }
		public string N { get; protected internal set; }
		public string H { get; protected internal set; }

		public string Seed { get; internal set; }

		public override ECDomainParameters GetParameters () {
			var n = new BigInteger (N, 16);
			var h = new BigInteger (H, 16);
			var curve = new FpCurve(new BigInteger(Q, 16), new BigInteger(A, 16), new BigInteger(B, 16), n, h);
			return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), n, h, 
				String.IsNullOrEmpty(Seed) ? null : Seed.HexToBinary());
		}
	}

	/// <summary>
	/// Information for a named elliptic curve over Fp 
	/// that uses a custom implementation for computations.
	/// </summary>
	public class CustomFpEcNamedCurveInformation : EcNamedCurveInformation
	{
		public Func<ECCurve> Curve { get; protected internal set; }

		public string G { get; protected internal set; }

		public string Seed { get; protected internal set; }

		public override ECDomainParameters GetParameters () {
			var curve = Curve ();
			return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), curve.Order, curve.Cofactor, 
				String.IsNullOrEmpty(Seed) ? null : Seed.HexToBinary());
		}
	}

	/// <summary>
	/// Information for a named elliptic curve over F2m with a trinomial polynomial basis (TPB).
	/// </summary>
	public class TpbF2mEcNamedCurveInformation : EcNamedCurveInformation
	{
		public int M { get; protected internal set; }
		public int K { get; protected internal set; }

		public string A { get; protected internal set; }
		public string B { get; protected internal set; }
		public string G { get; protected internal set; }

		public string N { get; protected internal set; }
		public string H { get; protected internal set; }

		public string Seed { get; protected internal set; }

		public override ECDomainParameters GetParameters () {
			var n = new BigInteger (N, 16);
			var h = new BigInteger (H, 16);
			var curve = new F2mCurve(M, K, new BigInteger(A, 16), new BigInteger(B, 16), n, h);
			return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), n, h, 
				String.IsNullOrEmpty(Seed) ? null : Seed.HexToBinary());
		}
	}

	/// <summary>
	/// Information for a named elliptic curve over F2m with a pentanomial polynomial basis (PPB).
	/// </summary>
	public class PpbF2mEcNamedCurveInformation : EcNamedCurveInformation
	{
		public int M { get; protected internal set; }
		public int K1 { get; protected internal set; }
		public int K2 { get; protected internal set; }
		public int K3 { get; protected internal set; }

		public string A { get; protected internal set; }
		public string B { get; protected internal set; }
		public string G { get; protected internal set; }

		public string N { get; protected internal set; }
		public string H { get; protected internal set; }

		public string Seed { get; protected internal set; }

		public override ECDomainParameters GetParameters () {
			var n = new BigInteger (N, 16);
			var h = new BigInteger (H, 16);
			var curve = new F2mCurve(M, K1, K2, K3, new BigInteger(A, 16), new BigInteger(B, 16), n, h);
			return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), n, h, 
				String.IsNullOrEmpty(Seed) ? null : Seed.HexToBinary());
		}
	}
}

