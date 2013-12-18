using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;

namespace ObscurCore.Cryptography.KeyAgreement
{
	/// <summary>
	/// Utillity methods for Elliptic-Curve-based key exchange/agreement schemes.
	/// </summary>
	public static class ECAgreementUtility
	{		
		public static AsymmetricCipherKeyPair GenerateKeyPair(ECDomainParameters parameters) {
			const string algorithm = "ECDHC";
			BigInteger n = parameters.N;
			BigInteger d;
			
			do { d = new BigInteger(n.BitLength, StratCom.EntropySource); }
			while (d.SignValue == 0 || (d.CompareTo(n) >= 0));
			
			ECPoint q = parameters.G.Multiply(d);
			
			return new AsymmetricCipherKeyPair(
				new ECPublicKeyParameters(algorithm, q, parameters),
				new ECPrivateKeyParameters(algorithm, d, parameters));
		}
		
		/// <summary>
		/// Calculates the shared secret in a Diffie-Hellman scheme with cofactor multiplication.
		/// </summary>
		/// <param name="domain">Domain parameters for the public and private keys provided.</param>
		/// <param name="Q">Public component of an EC keypair.</param>
        /// <param name="d">Private component of an EC keypair.</param>
		public static BigInteger CalculateDhcSecret(ECDomainParameters domain, 
		    ECPublicKeyParameters Q, ECPrivateKeyParameters d)
        {
			return Q.Q.Multiply(domain.H.Multiply(d.D)).X.ToBigInteger();
		}
		
		/// <summary>
		/// Calculates the shared secret in a Diffie-Hellman scheme.
		/// </summary>
        /// <param name="Q">Public component of an EC keypair.</param>
        /// <param name="d">Private component of an EC keypair.</param>
		public static BigInteger CalculateDhSecret(ECPublicKeyParameters Q, ECPrivateKeyParameters d) {
			return Q.Q.Multiply(d.D).X.ToBigInteger();
		}
	}
}

