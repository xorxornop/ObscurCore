using System.IO;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Extensions.Streams;

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
			
            // TODO: Review use of this unmodified, parameterless SecureRandom generator.
			do { d = new BigInteger(n.BitLength, new SecureRandom()); }
			while (d.SignValue == 0 || (d.CompareTo(n) >= 0));
			
			ECPoint q = parameters.G.Multiply(d);
			
			return new AsymmetricCipherKeyPair(
				new ECPublicKeyParameters(algorithm, q, parameters),
				new ECPrivateKeyParameters(algorithm, d, parameters));
		}
		
		/// <summary>
		/// Calculates the shared secret in a Diffie-Hellman scheme with cofactor multiplication.
		/// </summary>
		/// <param name="domain">Domain parameters for the public and private ECPoints (keys) provided.</param>
		/// <param name="Q">Public component of an EC keypair.</param>
        /// <param name="d">Private component of an EC keypair.</param>
		public static ECPoint CalculateDHCSecret(ECDomainParameters domain, 
		                                         ECPublicKeyParameters Q, ECPrivateKeyParameters d) {
			return Q.Q.Multiply(domain.H.Multiply(d.D));
		}
		
		/// <summary>
		/// Calculates the shared secret in a Diffie-Hellman scheme.
		/// </summary>
        /// <param name="domain">Domain parameters for the public and private ECPoints (keys) provided.</param>
        /// <param name="Q">Public component of an EC keypair.</param>
        /// <param name="d">Private component of an EC keypair.</param>
		public static ECPoint CalculateDHSecret(ECPublicKeyParameters Q, ECPrivateKeyParameters d) {
			return Q.Q.Multiply(d.D);
		}
	}

    /// <summary>
    /// Utility for reading and writing ECPoints to byte-array-encoded configurations.
    /// </summary>
    /// <remarks>
    /// Cannot be used in isolation unless domain parameters are invariant, 
    /// as they are not encoded with the point! Use a key agreement utility.
    /// </remarks>
    public static class ECKeyUtility
    {
        /// <summary>
        /// Reads and configures an ECPoint from a byte array format encoding, 
        /// given its associated domain parameters.
        /// </summary>
        /// <remarks>
        /// Domain parameters themselves are not encoded for efficiency reasons - 
        /// therefore, they must be externally supplied.
        /// </remarks>
        /// <param name='config'>Byte array encoding of configuration.</param>
        /// <param name='domain'>Domain parameters of the ECPoint to be read.</param>
        /// <param name='point'>ECPoint defining a point on an elliptic curve.</param>
        public static void Read (byte[] config, ECDomainParameters domain, out ECPoint point) {
            byte[] X1_bytes, Y1_bytes;
            using (var ms = new MemoryStream(config)) {
                ms.ReadPrimitive(out X1_bytes);
                ms.ReadPrimitive(out Y1_bytes);
            }
            var X1 = new BigInteger(X1_bytes);
            var Y1 = new BigInteger(Y1_bytes);
            // TODO: Check to see whether the generated BigIntegers represent the same length that the domain parameters do
            point = domain.Curve.CreatePoint(X1, Y1, false);
        }

        /// <summary>Writes an ECPoint to a byte array format encoding.</summary>
        /// <remarks>
        /// Domain parameters themselves are not encoded for efficiency reasons - 
        /// therefore, they must be externally supplied.
        /// </remarks>
        /// <param name="point">ECPoint defining a point on an elliptic curve.</param>
        /// <param name="output">Byte array encoding of configuration.</param>
        public static void Write (ECPoint point, out byte[] output) {
            using (var ms = new MemoryStream()) {
                ms.WritePrimitive(point.X.ToBigInteger().ToByteArray());
                ms.WritePrimitive(point.Y.ToBigInteger().ToByteArray());
                output = ms.ToArray();
            }
        }

        /// <summary>Writes an ECPoint to a byte array format encoding.</summary>
        /// <remarks>
        /// Domain parameters themselves are not encoded for efficiency reasons - 
        /// therefore, they must be externally supplied.
        /// </remarks>
        /// <param name='point'>ECPoint defining a point on an elliptic curve.</param>
        public static byte[] Write(ECPoint point) {
            byte[] output;
            Write(point, out output);
            return output;
        }
    }
}

