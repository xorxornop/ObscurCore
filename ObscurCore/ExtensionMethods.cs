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
    ///     Extension methods that should always be available (without namespace includes)
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

        public static int BytesToBits(this int byteLength)
        {
            return byteLength * 8;
        }

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
        /// Wraps a byte array in a <see cref="MemoryStream"/>.
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
            foreach (var candidate in candidates) {
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
            if (typeof (T).IsEnum == false) {
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

        private const int DeepCopyBufferBlockCopyThreshold = 16384;
#if INCLUDE_UNSAFE
        private const int DeepCopyUnmanagedThreshold = 128;
#endif

        public static byte[] DeepCopy(this byte[] data)
        {
            if (data == null) {
                return null;
            }
            var dst = new byte[data.Length];
            data.CopyBytes(0, dst, 0, data.Length);
            return dst;
        }

        public static void CopyBytes(this byte[] src, int srcOffset, byte[] dst, int dstOffset, int length)
        {
#if INCLUDE_UNSAFE
            if (length > DeepCopyUnmanagedThreshold) {
                if (srcOffset + length > src.Length || dstOffset + length > dst.Length) {
                    throw new ArgumentException(
                        "Either/both src or dst offset is incompatible with array length. Security risk in unsafe execution!");
                }
                unsafe {
                    fixed (byte* srcPtr = src) {
                        fixed (byte* dstPtr = dst) {
                            CopyMemory(dstPtr + dstOffset, srcPtr + srcOffset, length);
                        }
                    }
                }
            }
#else
            if (length > DeepCopyBufferBlockCopyThreshold) {
                Buffer.BlockCopy(src, srcOffset, dst, dstOffset, length);
            } else {
                Array.Copy(src, srcOffset, dst, dstOffset, length);
            }
#endif
        }

        public static int[] DeepCopy(this int[] data)
        {
            if (data == null) {
                return null;
            }
            var dst = new int[data.Length];
            data.DeepCopy(dst);
            return dst;
        }

        public static void DeepCopy(this int[] src, int[] dst)
        {
#if INCLUDE_UNSAFE
            const int limit = DeepCopyUnmanagedThreshold / sizeof(int);
            if (src.Length >= limit) {
                unsafe {
                    fixed (int* srcPtr = src) {
                        fixed (int* dstPtr = dst) {
                            var srcBP = (byte*)srcPtr;
                            var dstBP = (byte*)dstPtr;
                            CopyMemory(dstBP, srcBP, src.Length * sizeof(int));
                        }
                    }
                }
            }
#else
            const int limit = DeepCopyBufferBlockCopyThreshold / sizeof(ulong);
            if (src.Length >= limit)
                Buffer.BlockCopy(src, 0, dst, 0, src.Length);
            else
                Array.Copy(src, 0, dst, 0, src.Length);
#endif
        }

        public static long[] DeepCopy(this long[] data)
        {
            if (data == null) {
                return null;
            }
            var dst = new long[data.Length];
            data.DeepCopy(dst);
            return dst;
        }

        public static void DeepCopy(this long[] src, long[] dst)
        {
#if INCLUDE_UNSAFE
            const int limit = DeepCopyUnmanagedThreshold / sizeof(long);
            if (src.Length >= limit) {
                unsafe {
                    fixed (long* srcPtr = src) {
                        fixed (long* dstPtr = dst) {
                            var srcBP = (byte*)srcPtr;
                            var dstBP = (byte*)dstPtr;
                            CopyMemory(dstBP, srcBP, src.Length * sizeof(long));
                        }
                    }
                }
            }
#else
            const int limit = DeepCopyBufferBlockCopyThreshold / sizeof(long);
            if (src.Length >= limit)
                Buffer.BlockCopy(src, 0, dst, 0, src.Length);
            else
                Array.Copy(src, 0, dst, 0, src.Length);
#endif
        }

        public static ulong[] DeepCopy(this ulong[] data)
        {
            if (data == null) {
                return null;
            }
            var dst = new ulong[data.Length];
            data.DeepCopy(dst);
            return dst;
        }

        public static void DeepCopy(this ulong[] src, ulong[] dst)
        {
#if INCLUDE_UNSAFE
            const int limit = DeepCopyUnmanagedThreshold / sizeof(ulong);
            if (src.Length >= limit) {
                unsafe {
                    fixed (ulong* srcPtr = src) {
                        fixed (ulong* dstPtr = dst) {
                            var srcBP = (byte*)srcPtr;
                            var dstBP = (byte*)dstPtr;
                            CopyMemory(dstBP, srcBP, src.Length * sizeof(ulong));
                        }
                    }
                }
            }
#else
            const int limit = DeepCopyBufferBlockCopyThreshold / sizeof(ulong);
            if (src.Length >= limit)
                Buffer.BlockCopy(src, 0, dst, 0, src.Length);
            else
                Array.Copy(src, 0, dst, 0, src.Length);
#endif
        }

#if INCLUDE_UNSAFE
        internal static unsafe void CopyMemory(byte* dst, byte* src, int length)
        {
            while (length >= 16) {
                *(ulong*) dst = *(ulong*) src;
                dst += 8;
                src += 8;
                *(ulong*) dst = *(ulong*) src;
                dst += 8;
                src += 8;
                length -= 16;
            }

            if (length >= 8) {
                *(ulong*) dst = *(ulong*) src;
                dst += 8;
                src += 8;
                length -= 8;
            }

            if (length >= 4) {
                *(uint*) dst = *(uint*) src;
                dst += 4;
                src += 4;
                length -= 4;
            }

            if (length >= 2) {
                *(ushort*) dst = *(ushort*) src;
                dst += 2;
                src += 2;
                length -= 2;
            }

            if (length != 0) {
                *dst = *src;
            }
        }
#endif
    }

    public static class StreamExtensions
    {
        public static void WritePrimitive(this Stream stream, bool value)
        {
            stream.WriteByte(value ? (byte) 1 : (byte) 0);
        }

        public static void ReadPrimitive(this Stream stream, out bool value)
        {
            int b = stream.ReadByte();
            value = b != 0;
        }

        public static void WritePrimitive(this Stream stream, ushort value)
        {
            WriteVarint32(stream, value);
        }

        public static void ReadPrimitive(this Stream stream, out ushort value)
        {
            value = (ushort) ReadVarint32(stream);
        }

        public static void WritePrimitive(this Stream stream, short value)
        {
            WriteVarint32(stream, EncodeZigZag32(value));
        }

        public static void ReadPrimitive(this Stream stream, out short value)
        {
            value = (short) DecodeZigZag32(ReadVarint32(stream));
        }

        public static void WritePrimitive(this Stream stream, uint value)
        {
            WriteVarint32(stream, value);
        }

        public static void ReadPrimitive(this Stream stream, out uint value)
        {
            value = ReadVarint32(stream);
        }

        public static void WritePrimitive(this Stream stream, int value)
        {
            WriteVarint32(stream, EncodeZigZag32(value));
        }

        public static void ReadPrimitive(this Stream stream, out int value)
        {
            value = DecodeZigZag32(ReadVarint32(stream));
        }

        public static void WritePrimitive(this Stream stream, ulong value)
        {
            WriteVarint64(stream, value);
        }

        public static void ReadPrimitive(this Stream stream, out ulong value)
        {
            value = ReadVarint64(stream);
        }

        public static void WritePrimitive(this Stream stream, long value)
        {
            WriteVarint64(stream, EncodeZigZag64(value));
        }

        public static void ReadPrimitive(this Stream stream, out long value)
        {
            value = DecodeZigZag64(ReadVarint64(stream));
        }

#if INCLUDE_UNSAFE
        public static unsafe void WritePrimitive(this Stream stream, float value)
        {
            uint v = *(uint*) (&value);
            WriteVarint32(stream, v);
        }

        public static unsafe void ReadPrimitive(this Stream stream, out float value)
        {
            uint v = ReadVarint32(stream);
            value = *(float*) (&v);
        }

        public static unsafe void WritePrimitive(this Stream stream, double value)
        {
            ulong v = *(ulong*) (&value);
            WriteVarint64(stream, v);
        }

        public static unsafe void ReadPrimitive(this Stream stream, out double value)
        {
            ulong v = ReadVarint64(stream);
            value = *(double*) (&v);
        }
#endif

        private static uint EncodeZigZag32(int n)
        {
            return (uint) ((n << 1) ^ (n >> 31));
        }

        private static ulong EncodeZigZag64(long n)
        {
            return (ulong) ((n << 1) ^ (n >> 63));
        }

        private static int DecodeZigZag32(uint n)
        {
            return (int) (n >> 1) ^ -(int) (n & 1);
        }

        private static long DecodeZigZag64(ulong n)
        {
            return (long) (n >> 1) ^ -(long) (n & 1);
        }

        private static uint ReadVarint32(Stream stream)
        {
            int result = 0;
            int offset = 0;

            for (; offset < 32; offset += 7) {
                int b = stream.ReadByte();
                if (b == -1) {
                    throw new EndOfStreamException();
                }

                result |= (b & 0x7f) << offset;

                if ((b & 0x80) == 0) {
                    return (uint) result;
                }
            }

            throw new InvalidDataException();
        }

        private static void WriteVarint32(Stream stream, uint value)
        {
            for (; value >= 0x80u; value >>= 7) {
                stream.WriteByte((byte) (value | 0x80u));
            }

            stream.WriteByte((byte) value);
        }

        private static ulong ReadVarint64(Stream stream)
        {
            long result = 0;
            int offset = 0;

            for (; offset < 64; offset += 7) {
                int b = stream.ReadByte();
                if (b == -1) {
                    throw new EndOfStreamException();
                }

                result |= ((long) (b & 0x7f)) << offset;

                if ((b & 0x80) == 0) {
                    return (ulong) result;
                }
            }

            throw new InvalidDataException();
        }

        private static void WriteVarint64(Stream stream, ulong value)
        {
            for (; value >= 0x80u; value >>= 7) {
                stream.WriteByte((byte) (value | 0x80u));
            }

            stream.WriteByte((byte) value);
        }
    }
}