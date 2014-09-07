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
    public class ECDsaSigner : IDsa
    {
        protected static readonly ECMultiplier EcBasePointMultiplier = new FixedPointCombMultiplier();

        private readonly ECKey _publicKey;
        private readonly ECKey _privateKey;
        private ECDomainParameters _ecDomain;

        protected readonly IDsaKCalculator _kCalculator;
        private readonly CsRng _random;

        /// <summary>
        ///     Initialise for ECDSA signature generation.
        /// </summary>
        /// <param name="privateKey">
        ///     Private EC key used for signing (verification performed with corresponding public key).
        /// </param>
        /// <param name="random">
        ///     Supplier of random numbers (null for default is <see cref="StratCom.EntropySupplier"/>). 
        ///     Not used if <paramref name="kCalculator"/> is deterministic.
        /// </param>
        /// <param name="kCalculator">Calculator utility for generating k value in signature generation.</param>
        /// <seealso cref="HmacDsaKCalculator"/>
        public ECDsaSigner(ECKey privateKey, CsRng random = null, IDsaKCalculator kCalculator = null)
        {
            if (privateKey.PublicComponent) {
                throw new ArgumentException("EC private key required for signing.");
            }

            _privateKey = privateKey;
            _kCalculator = kCalculator ?? new RandomDsaKCalculator();
            if (_kCalculator.IsDeterministic == false) {
                _random = random ?? StratCom.EntropySupplier;
            }
        }

        /// <summary>
        ///     Initialise for (either) ECDSA signature generation or verification.
        /// </summary>
        /// <param name="forSigning">
        ///     If <c>true</c>, the instance will be used for signing.
        ///     If <c>false</c>, it will be used for verification.
        /// </param>
        /// <param name="key">Individual EC key.</param>
        /// <param name="random">
        ///     Supplier of random numbers (null for default is <see cref="StratCom.EntropySupplier"/>).
        /// </param>
        /// <param name="kCalculator">Calculator utility for generating k value in signature generation.</param>
        /// <seealso cref="HmacDsaKCalculator"/>
        public ECDsaSigner(bool forSigning, ECKey key, CsRng random = null, IDsaKCalculator kCalculator = null)
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

            _kCalculator = kCalculator ?? new RandomDsaKCalculator();
            if (forSigning && _kCalculator.IsDeterministic == false) {
                _random = random ?? StratCom.EntropySupplier;
            }

            SetupECDomain();
        }

        /// <summary>
        ///     Initialise for ECDSA signature generation and verification.
        /// </summary>
        /// <param name="publicKey">Public EC key (used for verifying) Null if not required.</param>
        /// <param name="privateKey">Private EC key (used for signing). Null if not required.</param>
        /// <param name="random">
        ///     Supplier of random numbers (null for default is <see cref="StratCom.EntropySupplier"/>).
        /// </param>
        /// <param name="kCalculator">Calculator utility for generating k value in signature generation.</param>
        /// <seealso cref="HmacDsaKCalculator"/>
        public ECDsaSigner(ECKey publicKey, ECKey privateKey, CsRng random = null, IDsaKCalculator kCalculator = null)
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
            _kCalculator = kCalculator ?? new RandomDsaKCalculator();
            if (_kCalculator.IsDeterministic == false) {
                _random = random ?? StratCom.EntropySupplier;
            }
            SetupECDomain();
        }

        private void SetupECDomain()
        {
            string curveName = _publicKey != null ? _publicKey.CurveName : _privateKey.CurveName;
            EcCurveInformation curveInfo;
            try {
                curveInfo = EcInformationStore.GetECCurveData(curveName);
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

            if (_kCalculator.IsDeterministic) {
                _kCalculator.Init(n, d, message);
            } else {
                _kCalculator.Init(n, _random);
            }

            // 5.3.2
            // Generate s
            do {
                BigInteger k;
                // Generate r
                do {
                    k = _kCalculator.NextK();
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
        ///     represent a valid ECDSA signature. Otherwise, <c>false</c>.
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
