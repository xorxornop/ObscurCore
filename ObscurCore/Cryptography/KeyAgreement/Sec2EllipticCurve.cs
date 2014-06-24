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

namespace ObscurCore.Cryptography.KeyAgreement
{
    /// <summary>
    ///     Named elliptic curves from SEC2 (Standards for Efficient Cryptography 2)
    /// </summary>
    /// <remarks>
    ///     The discerning user may wish to think twice about employing these curves,
    ///     particularly of the Koblitz form, due to security disclosures. They are
    ///     included for completeness and commonality.
    /// </remarks>
    public enum Sec2EllipticCurve
    {
        None,

        Secp160r1,

        Secp160r2,

        /// <summary>
        ///     192-bit Koblitz curve over F(p)
        /// </summary>
        Secp192k1,

        /// <summary>
        ///     192-bit curve over F(p)
        /// </summary>
        Secp192r1,

        /// <summary>
        ///     224-bit Koblitz curve over F(p)
        /// </summary>
        Secp224k1,

        /// <summary>
        ///     224-bit curve over F(p)
        /// </summary>
        Secp224r1,

        Sect163r1,

        Sect163r2,

        Sect193r1,

        Sect193r2,

        /// <summary>
        ///     233-bit Koblitz curve over F(2m)
        /// </summary>
        Sect233k1,

        /// <summary>
        ///     233-bit curve over F(2m)
        /// </summary>
        Sect233r1,

        Sect239k1,

        /// <summary>
        ///     224-bit Koblitz curve over F(p)
        /// </summary>
        Secp256k1,

        /// <summary>
        ///     256-bit curve over F(p)
        /// </summary>
        Secp256r1,

        /// <summary>
        ///     283-bit Koblitz curve over F(2m)
        /// </summary>
        Sect283k1,

        /// <summary>
        ///     283-bit curve over F(2m)
        /// </summary>
        Sect283r1,

        /// <summary>
        ///     384-bit curve over F(p)
        /// </summary>
        Secp384r1,

        /// <summary>
        ///     409-bit Koblitz curve over F(2m)
        /// </summary>
        Sect409k1,

        /// <summary>
        ///     409-bit curve over F(2m)
        /// </summary>
        Sect409r1,

        /// <summary>
        ///     521-bit curve over F(p)
        /// </summary>
        Secp521r1,

        /// <summary>
        ///     571-bit Koblitz curve over F(2m)
        /// </summary>
        Sect571k1,

        /// <summary>
        ///     571-bit curve over F(2m)
        /// </summary>
        Sect571r1
    }
}
