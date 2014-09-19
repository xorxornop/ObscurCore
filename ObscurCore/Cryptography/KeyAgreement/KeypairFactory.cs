#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using ObscurCore.Cryptography.Information;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.Signing.Primitives;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Multiplier;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyAgreement
{
    /// <summary>
    ///     Factory objects for creating keypairs used for key agreements.
    /// </summary>
    public static class KeypairFactory
    {
        internal static readonly ECMultiplier EcBasePointMultiplier = new FixedPointCombMultiplier();

        /// <summary>
        ///     Create a new elliptic curve keypair.
        /// </summary>
        /// <param name="curveName">Name of the elliptic curve to use as the basis.</param>
        /// <returns>Elliptic curve keypair.</returns>
        public static ECKeypair GenerateECKeypair(string curveName, bool generateCanary = true)
        {
            ECKeypair keypair;

            if (curveName.Equals(DjbCurve.Curve25519.ToString())) {
                var privEntropy = new byte[Curve25519.PrivateKeySeedSizeInBytes];
                StratCom.EntropySupplier.NextBytes(privEntropy);
                byte[] privateKey = Curve25519.CreatePrivateKey(privEntropy);
                byte[] publicKey = Curve25519.CreatePublicKey(privateKey);

                byte[] canary = null;
                if (generateCanary) {
                    canary = new byte[128.BitsToBytes()];
                    StratCom.EntropySupplier.NextBytes(canary);
                }

                keypair = new ECKeypair {
                    CurveProviderName = "DJB",
                    CurveName = DjbCurve.Curve25519.ToString(),
                    EncodedPublicKey = publicKey,
                    EncodedPrivateKey = privateKey,
                    UsePermissions = AsymmetricKeyUsePermission.KeyAgreements,
                    ContextPermissions = KeyUseContextPermission.ManifestHeader,
                    ConfirmationCanary = canary
                };
                privEntropy.SecureWipe();
            } else if (curveName.Equals(DjbCurve.Ed25519.ToString())) {
                var privEntropy = new byte[Ed25519.PrivateKeySeedSizeInBytes];
                StratCom.EntropySupplier.NextBytes(privEntropy);
                byte[] privateKey = new byte[Ed25519.ExpandedPrivateKeySizeInBytes];
                byte[] publicKey = new byte[Ed25519.PublicKeySizeInBytes];
                Ed25519.KeyPairFromSeed(out publicKey, out privateKey, privEntropy);

                byte[] canary = null;
                if (generateCanary) {
                    canary = new byte[128.BitsToBytes()];
                    StratCom.EntropySupplier.NextBytes(canary);
                }

                keypair = new ECKeypair {
                    CurveProviderName = "DJB",
                    CurveName = DjbCurve.Ed25519.ToString(),
                    EncodedPublicKey = publicKey,
                    EncodedPrivateKey = privateKey,
                    UsePermissions = AsymmetricKeyUsePermission.KeyAgreements | AsymmetricKeyUsePermission.Signatures,
                    ContextPermissions = KeyUseContextPermission.ManifestHeader,
                    ConfirmationCanary = canary
                };
            } else {
                ECPoint Q;
                BigInteger d;
                GenerateECKeypair(curveName, out Q, out d);

                byte[] canary = null;
                if (generateCanary) {
                    canary = new byte[128.BitsToBytes()];
                    StratCom.EntropySupplier.NextBytes(canary);
                }

                keypair = new ECKeypair {
                    CurveProviderName = EcInformationStore.GetProvider(curveName),
                    CurveName = curveName,
                    EncodedPublicKey = Q.GetEncoded(),
                    EncodedPrivateKey = d.ToByteArray(),
                    UsePermissions = AsymmetricKeyUsePermission.KeyAgreements | AsymmetricKeyUsePermission.Signatures,
                    ContextPermissions = KeyUseContextPermission.ManifestHeader,
                    ConfirmationCanary = canary
                };
            }

            return keypair;
        }

        /// <summary>
        ///     Create a new elliptic curve keypair.
        /// </summary>
        /// <param name="curveName">Name of the elliptic curve to use as the basis.</param>
        /// <param name="Q">Raw public key component.</param>
        /// <param name="d">Raw private key component.</param>
        /// <returns>Elliptic curve keypair.</returns>
        public static void GenerateECKeypair(string curveName, out ECPoint Q, out BigInteger d)
        {
            ECDomainParameters domain = Athena.Cryptography.EllipticCurves[curveName].GetParameters();
            GenerateECKeypair(domain, out Q, out d);
        }

        /// <summary>
        ///     Create a new elliptic curve keypair.
        /// </summary>
        /// <param name="domain">Elliptic curve to use as the basis.</param>
        /// <param name="Q">Raw public key component.</param>
        /// <param name="d">Raw private key component.</param>
        /// <returns>Elliptic curve keypair.</returns>
        public static void GenerateECKeypair(ECDomainParameters domain, out ECPoint Q, out BigInteger d)
        {
            ECPoint g = domain.G;
            BigInteger n = domain.N;
            int minWeight = n.BitLength >> 2;

            for (;;) {
                d = new BigInteger(n.BitLength, StratCom.EntropySupplier);

                if (d.CompareTo(BigInteger.Two) < 0 || d.CompareTo(n) >= 0) {
                    continue;
                }

                /*
                 * Require a minimum weight of the NAF representation, since low-weight primes may be
                 * weak against a version of the number-field-sieve for the discrete-logarithm-problem.
                 * 
                 * See "The number field sieve for integers of low weight", Oliver Schirokauer.
                 */
                if (WNafUtilities.GetNafWeight(d) < minWeight) {
                    continue;
                }

                break;
            }

            Q = EcBasePointMultiplier.Multiply(g, d);
        }

        /// <summary>
        ///     Get the public key corresponding to the private key <paramref name="d" />.
        /// </summary>
        /// <param name="d">Private key.</param>
        /// <param name="domain">Elliptic curve associated with <paramref name="d" />.</param>
        /// <returns>Public key as a raw EC point.</returns>
        public static ECPoint GetCorrespondingPublicKey(
            BigInteger d, ECDomainParameters domain)
        {
            ECPoint q = EcBasePointMultiplier.Multiply(domain.G, d);

            return q;
        }

        /// <summary>
        ///     Get the public key corresponding to the private key <paramref name="d" />.
        /// </summary>
        /// <param name="privKey">Private key.</param>
        /// <returns>Public key as a <see cref="ECPublicKeyParameters" /> object.</returns>
        public static ECPublicKeyParameters GetCorrespondingPublicKey(
            ECPrivateKeyParameters privKey)
        {
            ECDomainParameters ec = privKey.Parameters;
            ECPoint q = EcBasePointMultiplier.Multiply(ec.G, privKey.D);

            return new ECPublicKeyParameters(privKey.AlgorithmName, q, ec);
        }
    }
}
