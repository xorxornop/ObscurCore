//
//  Copyright 2013  Matthew Ducker
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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nessos.LinqOptimizer.CSharp;
using Obscur.Core.Support;

namespace Obscur.Core
{
    /// <summary>
    ///     Extension methods that provide basic functionality.
    /// </summary>
    public static class BasicExtensions
    {
        /// <summary>
        ///     Determines if value is between the specified low and high limits (range).
        /// </summary>
        /// <returns><c>true</c> if is between the specified value low high; otherwise, <c>false</c>.</returns>
        /// <param name="value">Value to check.</param>
        /// <param name="low">Low/minimum value.</param>
        /// <param name="high">High/maximum value.</param>
        /// <typeparam name="T">Type of value.</typeparam>
        public static bool IsBetween<T>(this T value, T low, T high) where T : IComparable<T>
        {
            return value.CompareTo(low) >= 0 && value.CompareTo(high) <= 0;
        }

        /// <summary>
        ///     Converts a byte-length representation to a bit-length representation.
        /// </summary>
        /// <param name="byteLength">Length in bytes.</param>
        /// <returns>Length in bits.</returns>
        public static int BytesToBits(this int byteLength)
        {
            return byteLength * 8;
        }

        /// <summary>
        ///     Converts a bit-length representation to a byte-length representation.
        /// </summary>
        /// <param name="bitLength">Length in bits.</param>
        /// <returns>Length in bytes.</returns>
        public static int BitsToBytes(this int bitLength)
        {
            return bitLength / 8;
        }

        


        /// <summary>
        ///     Parses an enumeration value encoded as a string into its enumeration equivalent.
        /// </summary>
        /// <returns>Enumeration value.</returns>
        /// <param name="stringValue">String to parse.</param>
        /// <param name="ignoreCase">If set to <c>true</c> ignore case; otherwise, <c>false</c>.</param>
        /// <typeparam name="T">Enumeration.</typeparam>
        /// <exception cref="InvalidOperationException">Type parameter is not an Enum.</exception>
        /// <exception cref="EnumerationParsingException">Supplied string not found as member in enumeration.</exception>
        public static T ToEnum<T>(this string stringValue, bool ignoreCase = true) where T : struct, IConvertible
        {
            if (typeof (T).IsEnum == false) {
                throw new InvalidOperationException("T must be an enumeration type.");
            }

            T value;
            try {
                value = (T) Enum.Parse(typeof (T), stringValue, ignoreCase);
            } catch (ArgumentException) {
                throw new EnumerationParsingException(stringValue, typeof (T));
            }
            return value;
        }

        /// <summary>
        ///     Determines if item/value equals one of the specified comparison candidate values/items.
        /// </summary>
        /// <returns><c>true</c> if is one of the specified candidates; otherwise, <c>false</c>.</returns>
        /// <param name="n">Item/value to compare.</param>
        /// <param name="candidates">Candidate items/values.</param>
        /// <param name="comparer">Optional - equality comparer.</param>
        public static bool IsOneOf<T>(this T n, IEnumerable<T> candidates, IEqualityComparer<T> comparer = null)
        {

            return comparer == null ? candidates.Contains(n) : candidates.Contains(n, comparer);
        }

        /// <summary>
        ///     Determines if string is/equals one of the specified comparison candidates.
        /// </summary>
        /// <returns><c>true</c> if is one of the specified candidates; otherwise, <c>false</c>.</returns>
        /// <param name="s">String to compare.</param>
        /// <param name="comparison">Comparison method.</param>
        /// <param name="candidates">Candidate strings.</param>
        public static bool StringIsOneOf(this string s, IEnumerable<string> candidates, StringComparison comparison)
        {
            return candidates.Any(candidate => candidate.Equals(s, comparison));
        }

        /// <summary>
        ///     Determines if number is/equals one of the specified comparison candidates.
        /// </summary>
        /// <returns><c>true</c> if is one of the specified candidates; otherwise, <c>false</c>.</returns>
        /// <param name="ns">Numbers to compar.e</param>
        /// <param name="candidates">Candidate numbers.</param>
        public static bool NumberIsOneOf(this IEnumerable<int> ns, IEnumerable<int> candidates)
        {
            var q = ns.AsQueryExpr().SelectMany(i => candidates, (i, candidate) => new {i, candidate})
                .Where(@t => @t.candidate == @t.i)
                .Select(@t => @t.i).Run();

            return q.Any();
        }

        /// <summary>
        ///     Determines if string is/equals a member in an enumeration.
        /// </summary>
        /// <returns><c>true</c> if is one of the specified candidates; otherwise, <c>false</c>.</returns>
        /// <param name="s">String to compare.</param>
        /// <param name="comparison">Comparison method (default: ordinal, ignore case).</param>
        /// <typeparam name="T">Enumeration.</typeparam>
        /// <exception cref="InvalidOperationException">Type parameter is not an Enum.</exception>
        public static bool IsMemberInEnum<T>(this string s,
            StringComparison comparison = StringComparison.OrdinalIgnoreCase) where T : struct, IConvertible
        {
            if (typeof(T).IsEnum == false) {
                throw new InvalidOperationException("Generic type T must be an enumeration type.");
            }

            string[] memberNames = Enum.GetNames(typeof (T));
            return s.StringIsOneOf(memberNames, comparison);
        }

        /// <summary>
        ///     Converts a byte array into a hex-encoded string.
        /// </summary>
        public static string ToHexString(this byte[] bytes)
        {
            return Hex.ToHexString(bytes);
        }

        /// <summary>
        ///     Converts a hex-encoded string to a byte array.
        /// </summary>
        /// <param name="hexSrc">Hex-encoded data</param>
        public static byte[] HexToBinary(this string hexSrc)
        {
            return Hex.Decode(hexSrc);
        }

        /// <summary>
        ///     Converts a byte array into a Base64-encoded string.
        /// </summary>
        public static string ToBase64String(this byte[] bytes, bool urlCompatible)
        {
            return urlCompatible ? Encoding.ASCII.GetString(UrlBase64.Encode(bytes)) : Base64.ToBase64String(bytes);
        }

        /// <summary>
        ///     Converts a hex-encoded string to a byte array.
        /// </summary>
        /// <param name="b64Src">Base64-encoded data</param>
        /// <param name="urlEncoded"></param>
        public static byte[] Base64ToBinary(this string b64Src, bool urlEncoded)
        {
            if (b64Src == null) {
                return null;
            }

            return urlEncoded ? UrlBase64.Decode(b64Src) : Base64.Decode(b64Src);
        }
    }
}
