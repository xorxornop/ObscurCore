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

using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Support;

namespace ObscurCore.Cryptography.Information.EllipticCurve
{
    /// <summary>
    ///     Information about a named elliptic curve.
    /// </summary>
    public abstract class EcCurveInformation
    {
        public enum CurveField
        {
            Fp,
            TpbF2m,
            PpbF2m,
            Other
        }

        /// <summary>
        ///     Field form of the curve.
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