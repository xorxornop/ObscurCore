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

namespace ObscurCore.Cryptography.KeyAgreement
{
    /// <summary>
    ///     Named elliptic curves over F(<sub>p</sub>) and F(<sub>2</sub>m) from SEC2 (Standards for Efficient Cryptography 2). 
    ///     Also known as NIST curves.
    /// </summary>
    /// <remarks>
    ///     The discerning user may wish to think twice about employing these curves,
    ///     particularly of the Koblitz form, due to security disclosures. They are
    ///     included for commonality and completeness. 
    ///     Some curves are preferred over others; refer to the individual curves for further information.
    /// </remarks>
    public enum Sec2EllipticCurve
    {
        /// <summary>
        ///     160-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        Secp160r1,

        /// <summary>
        ///     160-bit prime field curve over F(<sub>p</sub>) (revised from <see cref="Secp160r1"/>)
        /// </summary>
        Secp160r2,

        /// <summary>
        ///     192-bit prime field Koblitz curve over F(<sub>p</sub>)
        /// </summary>
        Secp192k1,

        /// <summary>
        ///     192-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        Secp192r1,

        /// <summary>
        ///     224-bit prime field Koblitz curve over F(<sub>p</sub>)
        /// </summary>
        Secp224k1,

        /// <summary>
        ///     NIST P-224. 224-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        Secp224r1,

        /// <summary>
        ///     256-bit prime field Koblitz curve over F(<sub>p</sub>)
        /// </summary>
        /// <remarks>
        ///     Recommended over the other NIST curves.
        /// </remarks>
        Secp256k1,

        /// <summary>
        ///     NIST P-256. 256-bit prime field curve over F(<sub>p</sub>).
        /// </summary>
        Secp256r1,

        /// <summary>
        ///     NIST P-384. 384-bit prime field curve over F(<sub>p</sub>).
        /// </summary>
        Secp384r1,

        /// <summary>
        ///     NIST P-521. 521-bit prime field curve over F(<sub>p</sub>).
        /// </summary>
        Secp521r1,

        /// <summary>
        ///     163-bit curve over F(<sub>2</sub>m)
        /// </summary>
        Sect163r1,

        /// <summary>
        ///     NIST B-163. 163-bit curve over F(<sub>2</sub>m) (revised from <see cref="Sect163r1"/>)
        /// </summary>
        Sect163r2,

        /// <summary>
        ///     193-bit curve over F(<sub>2</sub>m)
        /// </summary>
        Sect193r1,

        /// <summary>
        ///     193-bit curve over F(<sub>2</sub>m) (revised from <see cref="Sect193r1"/>)
        /// </summary>
        Sect193r2,

        /// <summary>
        ///     NIST K-233. 233-bit Koblitz curve over F(<sub>2</sub>m)
        /// </summary>
        Sect233k1,

        /// <summary>
        ///     NIST B-233. 233-bit curve over F(<sub>2</sub>m)
        /// </summary>
        Sect233r1,

        /// <summary>
        ///     239-bit Koblitz curve over F(<sub>2</sub>m)
        /// </summary>
        Sect239k1,

        /// <summary>
        ///     NIST K-283. 283-bit Koblitz curve over F(<sub>2</sub>m)
        /// </summary>
        Sect283k1,

        /// <summary>
        ///     NIST B-283. 283-bit curve over F(<sub>2</sub>m)
        /// </summary>
        Sect283r1,

        /// <summary>
        ///     NIST K-409. 409-bit Koblitz curve over F(<sub>2</sub>m)
        /// </summary>
        Sect409k1,

        /// <summary>
        ///     NIST B-409. 409-bit curve over F(<sub>2</sub>m)
        /// </summary>
        Sect409r1,

        /// <summary>
        ///     NIST K-571. 571-bit Koblitz curve over F(<sub>2</sub>m)
        /// </summary>
        Sect571k1,

        /// <summary>
        ///     NIST B-571. 571-bit curve over F(<sub>2</sub>m)
        /// </summary>
        Sect571r1
    }
}
