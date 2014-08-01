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
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;

namespace ObscurCore.Cryptography.KeyAgreement.Information
{
    /// <summary>
    ///     Information for a named elliptic curve over Fp.
    /// </summary>
    public class FpEcNamedCurveInformation : EllipticCurveInformation
    {
        public FpEcNamedCurveInformation()
        {
            Field = CurveField.Fp;
        }

        public string Q { get; protected internal set; }
        public string A { get; protected internal set; }
        public string B { get; protected internal set; }

        /// <summary>
        ///     Base point
        /// </summary>
        public string G { get; protected internal set; }

        /// <summary>
        ///     Order
        /// </summary>
        public string N { get; protected internal set; }

        /// <summary>
        ///     Cofactor
        /// </summary>
        public string H { get; protected internal set; }

        public string Seed { get; internal set; }

        /// <inheritdoc />
        public override ECDomainParameters GetParameters()
        {
            var n = new BigInteger(N, 16);
            var h = new BigInteger(H, 16);
            var curve = new FpCurve(new BigInteger(Q, 16), new BigInteger(A, 16), new BigInteger(B, 16), n, h);
            return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), n, h,
                String.IsNullOrEmpty(Seed) ? null : Seed.HexToBinary());
        }
    }
}