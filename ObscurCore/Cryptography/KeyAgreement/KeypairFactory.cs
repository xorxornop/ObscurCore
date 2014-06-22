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

using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Multiplier;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyAgreement
{
    public static class KeypairFactory
    {
        internal static readonly ECMultiplier EcBasePointMultiplier = new FixedPointCombMultiplier();

        public static EcKeypair GenerateEcKeypair(string curveName)
        {
            EcKeypair keypair;

            if (curveName.Equals(DjbCurve.Curve25519.ToString())) {
                var privEntropy = new byte[32];
                StratCom.EntropySupplier.NextBytes(privEntropy);
                byte[] privateKey = Curve25519.CreatePrivateKey(privEntropy);
                byte[] publicKey = Curve25519.CreatePublicKey(privateKey);

                keypair = new EcKeypair {
                    CurveProviderName = "DJB",
                    CurveName = DjbCurve.Curve25519.ToString(),
                    EncodedPublicKey = publicKey,
                    EncodedPrivateKey = privateKey
                };
            } else {
                ECPoint Q;
                BigInteger d;
                GenerateEcKeypair(curveName, out Q, out d);

                keypair = new EcKeypair {
                    CurveProviderName = NamedEllipticCurves.GetProvider(curveName),
                    CurveName = curveName,
                    EncodedPublicKey = Q.GetEncoded(),
                    EncodedPrivateKey = d.ToByteArray()
                };
            }

            return keypair;
        }

        internal static void GenerateEcKeypair(string curveName, out ECPoint Q, out BigInteger d)
        {
            ECDomainParameters domain = NamedEllipticCurves.Curves[curveName].GetParameters();
            GenerateEcKeypair(domain, out Q, out d);
        }

        internal static void GenerateEcKeypair(ECDomainParameters domain, out ECPoint Q, out BigInteger d)
        {
            ECPoint g = domain.G;
            BigInteger n = domain.N;
            int minWeight = n.BitLength >> 2;

            do {
                do {
                    d = new BigInteger(n.BitLength, StratCom.EntropySupplier);
                    /*
                     * WNAF requirement in while condition:
                     * A minimum weight of the NAF representation, since low-weight primes may be 
                     * weak against a version of the number-field-sieve for the discrete-logarithm-problem.
                     * 
                     * See "The number field sieve for integers of low weight", Oliver Schirokauer.
                     */
                } while ((d.CompareTo(BigInteger.Two) < 0 || d.CompareTo(n) >= 0) &&
                         WNafUtilities.GetNafWeight(d) < minWeight);
            } while (d.SignValue == 0 || (d.CompareTo(n) >= 0));

            Q = EcBasePointMultiplier.Multiply(g, d);
        }
    }
}
