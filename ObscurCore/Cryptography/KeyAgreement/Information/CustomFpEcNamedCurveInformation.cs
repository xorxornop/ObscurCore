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
using Nessos.LinqOptimizer.CSharp;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Endomorphism;

namespace ObscurCore.Cryptography.KeyAgreement.Information
{
    /// <summary>
    ///     Information for a named elliptic curve over Fp
    ///     that uses a custom implementation for computations.
    /// </summary>
    public class CustomFpEcNamedCurveInformation : EllipticCurveInformation
    {
        protected readonly Func<ECCurve> CurveFunc;
        protected readonly GlvTypeBParameters GlvParameters;

        /// <summary>
        ///     Create a new instance of the custom-implementation Fp curve information class,
        ///     CustomFpEcNamedCurveInformation.
        /// </summary>
        /// <param name="curve">Custom curve function.</param>
        /// <param name="glvParams">GLV endomorphism parameters, if any.</param>
        public CustomFpEcNamedCurveInformation(Func<ECCurve> curve, GlvTypeBParameters glvParams = null)
        {
            Field = CurveField.Fp;
            GlvParameters = glvParams;

            if (GlvParameters != null) {
                CurveFunc = () => {
                    ECCurve c = curve();
                    c.Configure().SetEndomorphism(new GlvTypeBEndomorphism(c, GlvParameters)).Create();
                    return c;
                };
            } else {
                CurveFunc = curve;
            }
        }

        /// <summary>
        ///     Base point
        /// </summary>
        public string G { get; protected internal set; }

        public string Seed { get; protected internal set; }

        /// <inheritdoc />
        public override ECDomainParameters GetParameters()
        {
            ECCurve curve = CurveFunc();
            return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), curve.Order, curve.Cofactor,
                String.IsNullOrEmpty(Seed) ? null : Seed.HexToBinary());
        }

        public static GlvTypeBParameters CreateEndomorphismParameters(string beta, string lambda, string[] v1,
            string[] v2, string g1, string g2, int bits)
        {
            BigInteger[] v1_ = v1.AsQueryExpr().Select(s => new BigInteger(s, 16)).ToArray().Run();
            BigInteger[] v2_ = v2.AsQueryExpr().Select(s => new BigInteger(s, 16)).ToArray().Run();

            return new GlvTypeBParameters(
                new BigInteger(beta, 16),
                new BigInteger(lambda, 16),
                v1_,
                v2_,
                new BigInteger(g1, 16),
                new BigInteger(g2, 16),
                bits);
        }
    }
}