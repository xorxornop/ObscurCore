#region License

// 	Copyright 2013-2014 Matthew Ducker
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

using Obscur.Core.Cryptography.Support;
using Obscur.Core.Cryptography.Support.Math;
using Obscur.Core.Support;

namespace Obscur.Core.Cryptography.Information.EllipticCurve
{
    /// <summary>
    ///     Information about a named elliptic curve.
    /// </summary>
    public abstract class EcCurveInformation
    {
        public enum CurveField
        {
            /// <summary>
            /// Elliptic curve over the prime finite field F(<sub>p</sub>).
            /// </summary>
            Fp,

            /// <summary>
            /// Elliptic curve over the binary finite field F(<sub>2</sub>)m with a trinomial polynomial basis (TPB).
            /// </summary>
            TpbF2m,

            /// <summary>
            /// Elliptic curve over the binary finite field F(<sub>2</sub>)m with a pentanomial polynomial basis (PPB).
            /// </summary>
            PpbF2m,

            /// <summary>
            /// Elliptic curve over a field other than F(<sub>p</sub>) or F(<sub>2</sub>)m.
            /// </summary>
            Other
        }

        /// <summary>
        ///     Field form of the curve (what field the curve is over).
        /// </summary>
        public CurveField Field { get; protected internal set; }

        /// <summary>
        ///     Name of the elliptic curve.
        /// </summary>
        public string Name { get; protected internal set; }

        /// <summary>
        ///     Name to show a user or for a detailed specification.
        /// </summary>
        public string DisplayName { get; protected internal set; }

        /// <summary>
        ///     Bit length of a curve point representation.
        /// </summary>
        public int BitLength { get; protected internal set; }

        /// <summary>
        ///     Get parameter object for performing computations.
        /// </summary>
        /// <returns></returns>
        public abstract ECDomainParameters GetParameters();

        /// <summary>
        ///     Convert a hex representation of an integer into a <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="hex">Hex representation.</param>
        protected static BigInteger FromHex(string hex)
        {
            return new BigInteger(1, Hex.Decode(hex));
        }
    }
}