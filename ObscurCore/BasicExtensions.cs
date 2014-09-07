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
using System.IO;
using System.Text;
using ObscurCore.Support;

namespace ObscurCore
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
        ///     Converts a byte-length representation to a bit representation.
        /// </summary>
        /// <param name="byteLength">Length in bytes.</param>
        /// <returns>Length in bits.</returns>
        public static int BytesToBits(this int byteLength)
        {
            return byteLength * 8;
        }

        /// <summary>
        ///     Converts a bit-length representation to a byte representation.
        /// </summary>
        /// <param name="bitLength">Length in bits.</param>
        /// <returns>Length in bytes.</returns>
        public static int BitsToBytes(this int bitLength)
        {
            return bitLength / 8;
        }

        /// <summary>
        ///     Determines if specified array is null or zero length.
        /// </summary>
        /// <returns><c>true</c> if is null or zero length; otherwise, <c>false</c>.</returns>
        /// <param name="array">Array to check.</param>
        public static bool IsNullOrZeroLength<T>(this T[] array)
        {
            return array == null || array.Length == 0;
        }

        /// <summary>
        ///     Wraps a byte array in a <see cref="MemoryStream" />.
        /// </summary>
        /// <param name="data">Data to wrap.</param>
        /// <param name="writeable">If <c>true</c>, additional data can be written to the stream after creation.</param>
        /// <returns></returns>
        public static MemoryStream ToMemoryStream(byte[] data, bool writeable = true)
        {
            return new MemoryStream(data, writeable);
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
        ///     Determines if string is/equals one of the specified comparison candidates.
        /// </summary>
        /// <returns><c>true</c> if is one of the specified candidates; otherwise, <c>false</c>.</returns>
        /// <param name="s">String to compare</param>
        /// <param name="comparison">Comparison method</param>
        /// <param name="candidates">Candidate strings</param>
        public static bool IsOneOf(this string s, IEnumerable<string> candidates, StringComparison comparison)
        {
            foreach (string candidate in candidates) {
                if (candidate.Equals(s, comparison)) {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        ///     Determines if number is/equals one of the specified comparison candidates.
        /// </summary>
        /// <returns><c>true</c> if is one of the specified candidates; otherwise, <c>false</c>.</returns>
        /// <param name="n">Number to compare</param>
        /// <param name="candidates">Candidate strings</param>
        public static bool IsOneOf(this int n, IEnumerable<int> candidates)
        {
            foreach (int candidate in candidates) {
                if (candidate == n) {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        ///     Determines if string is/equals a member in an enumeration.
        /// </summary>
        /// <returns><c>true</c> if is one of the specified candidates; otherwise, <c>false</c>.</returns>
        /// <param name="s">String to compare.</param>
        /// <param name="comparison">Comparison method.</param>
        /// <typeparam name="T">Enumeration.</typeparam>
        /// <exception cref="InvalidOperationException">Type parameter is not an Enum.</exception>
        public static bool IsMemberInEnum<T>(this string s,
            StringComparison comparison = StringComparison.OrdinalIgnoreCase) where T : struct, IConvertible
        {
            if (typeof(T).IsEnum == false) {
                throw new InvalidOperationException("T must be an enumeration type.");
            }

            string[] memberNames = Enum.GetNames(typeof (T));
            return s.IsOneOf(memberNames, comparison);
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
            if (hexSrc == null) {
                return null;
            }

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


        public static int GetHashCodeExt(this byte[] data)
        {
            return data.GetHashCodeExt(0, data.Length);
        }

        public static int GetHashCodeExt(this byte[] data, int off, int count)
        {
            if (data == null) {
                return 0;
            }

            int i = off + count;
            int hc = count + 1;

            while (--i >= 0) {
                hc *= 257;
                hc ^= data[i];
            }

            return hc;
        }

        public static int GetHashCodeExt(this int[] data)
        {
            return data.GetHashCodeExt(0, data.Length);
        }

        public static int GetHashCodeExt(this int[] data, int off, int count)
        {
            if (data == null) {
                return 0;
            }

            int i = off + count;
            int hc = count + 1;

            while (--i >= 0) {
                hc *= 257;
                hc ^= data[i];
            }

            return hc;
        }

        public static int GetHashCodeExt(this uint[] data)
        {
            return data.GetHashCodeExt(0, data.Length);
        }

        public static int GetHashCodeExt(this uint[] data, int off, int count)
        {
            if (data == null) {
                return 0;
            }

            int i = off + count;
            int hc = count + 1;

            while (--i >= 0) {
                hc *= 257;
                hc ^= (int) data[i];
            }

            return hc;
        }

        /// <summary>
        /// Compare two byte arrays in varying time (terminates early if mis-match found). 
        /// Array <paramref name="a"/> should be the longer of the two, if they are different, 
        /// as its length is used.
        /// </summary>
        /// <param name="a">First byte array.</param>
        /// <param name="b">Second byte array.</param>
        /// <returns><c>true</c> if arrays are equal, <c>false</c> otherwise.</returns>
        public static bool SequenceEqualShortCircuiting(this byte[] a, byte[] b)
        {
            int i = a.Length;
            if (i != b.Length) {
                return false;
            }
            while (i != 0) {
                --i;
                if (a[i] != b[i]) {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Compare two arrays in varying time (terminates early if mis-match found). 
        /// Array <paramref name="a"/> should be the longer of the two, if they are different, 
        /// as its length is used.
        /// </summary>
        /// <param name="a">First array.</param>
        /// <param name="b">Second array.</param>
        /// <returns><c>true</c> if arrays are equal, <c>false</c> otherwise.</returns>
        public static bool SequenceEqualShortCircuiting<T>(this T[] a, T[] b) where T : struct
        {
            int i = a.Length;
            if (i != b.Length) {
                return false;
            }
            while (i != 0) {
                --i;
                if (!a[i].Equals(b[i])) {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        ///     Fill <paramref name="array"/> with <paramref name="value"/>.
        /// </summary>
        /// <typeparam name="T">Type of <paramref name="array"/> and <paramref name="value"/>.</typeparam>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        public static void FillArray<T>(this T[] array, T value) where T : struct
        {
            FillArray(array, value, 0, array.Length);
        }

        /// <summary>
        ///     Fill <paramref name="array"/> from <paramref name="offset"/> with 
        ///     <paramref name="length"/> repeats of <paramref name="value"/>.
        /// </summary>
        /// <typeparam name="T">Type of <paramref name="array"/> and <paramref name="value"/>.</typeparam>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        /// <param name="offset">Offset in <paramref name="array"/> to fill from.</param>
        /// <param name="length">Repeats of <paramref name="value"/> to write.</param>
        public static void FillArray<T>(this T[] array, T value, int offset, int length) where T : struct
        {
            int endOffset = offset + length;
            for (int i = offset; i < endOffset; i++) {
                array[i] = value;
            }
        }
    }
}
