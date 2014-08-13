#region License

// 	Copyright 2014-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

#endregion

using System;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Information;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Multiplier;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Signing.Primitives
{
    /// <summary>
    ///     EC-DSA as described in X9.62 .
    /// </summary>
    /// <remarks>
    ///     Implementation is as recommended in X9.62 <see cref="http://www.x9.org/" />
    ///     (Accredited Standards Committee: American National Standard X9.62-2005,
    ///     Public Key Cryptography for the Financial Services Industry,
    ///     The Elliptic Curve Digital Signature Algorithm (ECDSA), November 16, 2005) .
    /// </remarks>
    public class EcDsaSigner : IDsa
    {
        protected static readonly ECMultiplier EcBasePointMultiplier = new FixedPointCombMultiplier();
        private readonly EcKeyConfiguration _publicKey;
        private readonly EcKeyConfiguration _privateKey;
        private ECDomainParameters _ecDomain;

        private readonly CsRng _random = StratCom.EntropySupplier;

        /// <summary>
        ///     Initialise for either ECDSA signature generation or ECDSA signature verification.
        /// </summary>
        /// <param name="forSigning">
        ///     If <c>true</c>, the instance will be used for signing.
        ///     If <c>false</c>, it will be used for verification.
        /// </param>
        /// <param name="key">Individual EC key.</param>
        /// <param name="entropy">
        ///     Supplier of random numbers (null for default <see cref="StratCom.EntropySupplier" />).
        /// </param>
        public EcDsaSigner(bool forSigning, EcKeyConfiguration key, CsRng entropy = null)
        {
            if (key == null) {
                throw new ArgumentNullException("key");
            }

            if (forSigning) {
                if (key.PublicComponent) {
                    throw new ArgumentException("EC private key required for signing.");
                }
                _privateKey = key;
            } else {
                if (key.PublicComponent == false) {
                    throw new ArgumentException("EC public key required for verification.");
                }
            }

            _random = entropy ?? StratCom.EntropySupplier;

            SetupEcDomain();
        }

        /// <summary>
        ///     Initialise for ECDSA signature generation and ECDSA signature verification.
        /// </summary>
        /// <param name="publicKey">Public EC key (used for verifying) Null if not required.</param>
        /// <param name="privateKey">Private EC key (used for signing). Null if not required.</param>
        /// <param name="entropy">
        ///     Supplier of random numbers (null for default <see cref="StratCom.EntropySupplier" />).
        /// </param>
        public EcDsaSigner(EcKeyConfiguration publicKey, EcKeyConfiguration privateKey, CsRng entropy = null)
        {
            if (publicKey != null && privateKey != null) {
                throw new ArgumentNullException();
            }

            if (publicKey != null) {
                if (publicKey.PublicComponent == false) {
                    throw new ArgumentException("Not a public EC key.", "publicKey");
                }
            }
            if (privateKey != null) {
                if (privateKey.PublicComponent) {
                    throw new ArgumentException("Not a private EC key.", "privateKey");
                }
            }

            _publicKey = publicKey;
            _privateKey = privateKey;
            SetupEcDomain();
        }

        private void SetupEcDomain()
        {
            string curveName = _publicKey != null ? _publicKey.CurveName : _privateKey.CurveName;
            EllipticCurveInformation curveInfo;
            try {
                curveInfo = EllipticCurveInformationStore.GetEcCurveData(curveName);
            } catch (Exception e) {
                throw new ConfigurationInvalidException("Curve cannot be used in ECDSA.", e);
            }
            _ecDomain = curveInfo.GetParameters();
        }

        /// <inheritdoc />
        public bool SigningCapable
        {
            get { return _privateKey != null; }
        }

        /// <inheritdoc />
        public bool VerificationCapable
        {
            get { return _publicKey != null; }
        }

        /// <inheritdoc />
        public string AlgorithmName
        {
            get { return "ECDSA"; }
        }

        /// <inheritdoc />
        public void GenerateSignature(byte[] message, out BigInteger r, out BigInteger s)
        {
            BigInteger n = _ecDomain.N;
            BigInteger e = CalculateE(n, message);
            var d = new BigInteger(_privateKey.EncodedKey);

            // 5.3.2
            // Generate s
            do {
                BigInteger k;
                // Generate r
                do {
                    do {
                        k = new BigInteger(n.BitLength, _random);
                    } while (k.SignValue == 0 || k.CompareTo(n) >= 0);

                    ECPoint p = EcBasePointMultiplier.Multiply(_ecDomain.G, k).Normalize();

                    // 5.3.3
                    r = p.AffineXCoord.ToBigInteger().Mod(n);
                } while (r.SignValue == 0);

                s = k.ModInverse(n).Multiply(e.Add(d.Multiply(r))).Mod(n);
            } while (s.SignValue == 0);
        }

        /// <inheritdoc />
        /// <returns>
        ///     <c>true</c> if the values <paramref name="r" /> and <paramref name="s" />
        ///     represent a valid DSA signature. Otherwise, <c>false</c>.
        /// </returns>
        public bool VerifySignature(
            byte[] message,
            BigInteger r,
            BigInteger s)
        {
            BigInteger n = _ecDomain.N;

            // r and s should both in the range [1,n-1]
            if (r.SignValue < 1 || s.SignValue < 1
                || r.CompareTo(n) >= 0 || s.CompareTo(n) >= 0) {
                return false;
            }

            BigInteger e = CalculateE(n, message);
            BigInteger c = s.ModInverse(n);

            BigInteger u1 = e.Multiply(c).Mod(n);
            BigInteger u2 = r.Multiply(c).Mod(n);

            ECPoint G = _ecDomain.G;
            ECPoint Q = _ecDomain.Curve.DecodePoint(_publicKey.EncodedKey);

            ECPoint point = ECAlgorithms.SumOfTwoMultiplies(G, u1, Q, u2).Normalize();

            if (point.IsInfinity) {
                return false;
            }

            BigInteger v = point.AffineXCoord.ToBigInteger().Mod(n);

            return v.Equals(r);
        }

        private static BigInteger CalculateE(
            BigInteger n,
            byte[] message)
        {
            int messageBitLength = message.Length * 8;
            var trunc = new BigInteger(1, message);

            if (n.BitLength < messageBitLength) {
                trunc = trunc.ShiftRight(messageBitLength - n.BitLength);
            }

            return trunc;
        }
    }
}
