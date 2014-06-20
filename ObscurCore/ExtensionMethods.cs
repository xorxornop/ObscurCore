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
using ObscurCore.DTO;
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
        ///     Serialises the dto.
        /// </summary>
        /// <returns>The serialised DTO in a byte array.</returns>
        /// <param name="obj">Object to serialise.</param>
        /// <param name="prefixLength">If set to <c>true</c> prefix length of object to output; otherwise, <c>false</c>.</param>
        /// <typeparam name="T">The 1st type parameter.</typeparam>
        public static byte[] SerialiseDto<T>(this T obj, bool prefixLength = false) where T : IDataTransferObject
        {
            return StratCom.SerialiseDataTransferObject(obj, prefixLength).ToArray();
        }

        public static void SerialiseDto<T>(this T obj, Stream output, bool prefixLength = false)
            where T : IDataTransferObject
        {
            StratCom.SerialiseDataTransferObject(obj, output, prefixLength);
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

        [CLSCompliant(false)]
        public static int GetHashCodeExt(this uint[] data)
        {
            return data.GetHashCodeExt(0, data.Length);
        }

        [CLSCompliant(false)]
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

        private const int DeepCopyUnsafeLimit = 16384;

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
#else
            if (src.Length > DeepCopyUnsafeLimit) {
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
            unsafe {
                fixed (int* srcPtr = src) {
                    fixed (int* dstPtr = dst) {
                        var srcBP = (byte*) srcPtr;
                        var dstBP = (byte*) dstPtr;
                        CopyMemory(dstBP, srcBP, src.Length * sizeof (int));
                    }
                }
            }
#else
            const int limit = DeepCopyUnsafeLimit / sizeof(ulong);
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
            unsafe {
                fixed (long* srcPtr = src) {
                    fixed (long* dstPtr = dst) {
                        var srcBP = (byte*) srcPtr;
                        var dstBP = (byte*) dstPtr;
                        CopyMemory(dstBP, srcBP, src.Length * sizeof (long));
                    }
                }
            }
#else
            const int limit = DeepCopyUnsafeLimit / sizeof(long);
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
            unsafe {
                fixed (ulong* srcPtr = src) {
                    fixed (ulong* dstPtr = dst) {
                        var srcBP = (byte*) srcPtr;
                        var dstBP = (byte*) dstPtr;
                        CopyMemory(dstBP, srcBP, src.Length * sizeof (ulong));
                    }
                }
            }
#else
            const int limit = DeepCopyUnsafeLimit / sizeof(ulong);
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
}

namespace ObscurCore.Extensions
{
    namespace Streams
    {
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

            public static void WritePrimitive(this Stream stream, byte value)
            {
                stream.WriteByte(value);
            }

            public static void ReadPrimitive(this Stream stream, out byte value)
            {
                value = (byte) stream.ReadByte();
            }

            public static void WritePrimitive(this Stream stream, sbyte value)
            {
                stream.WriteByte((byte) value);
            }

            public static void ReadPrimitive(this Stream stream, out sbyte value)
            {
                value = (sbyte) stream.ReadByte();
            }

            public static void WritePrimitive(this Stream stream, char value)
            {
                WriteVarint32(stream, value);
            }

            public static void ReadPrimitive(this Stream stream, out char value)
            {
                value = (char) ReadVarint32(stream);
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

            public static void WritePrimitive(this Stream stream, DateTime value)
            {
                long v = value.ToBinary();
                WritePrimitive(stream, v);
            }

            public static void ReadPrimitive(this Stream stream, out DateTime value)
            {
                long v;
                ReadPrimitive(stream, out v);
                value = DateTime.FromBinary(v);
            }

            public static void WritePrimitive(this Stream stream, string value)
            {
                if (value == null) {
                    WritePrimitive(stream, (uint) 0);
                    return;
                }

                var encoding = new UTF8Encoding(false, true);

                int len = encoding.GetByteCount(value);

                WritePrimitive(stream, (uint) len + 1);

                var buf = new byte[len];

                encoding.GetBytes(value, 0, value.Length, buf, 0);

                stream.Write(buf, 0, len);
            }

            public static void ReadPrimitive(this Stream stream, out string value)
            {
                uint len;
                ReadPrimitive(stream, out len);

                switch (len) {
                    case 0:
                        value = null;
                        return;
                    case 1:
                        value = string.Empty;
                        return;
                }

                len -= 1;

                var encoding = new UTF8Encoding(false, true);

                var buf = new byte[len];

                int l = 0;

                while (l < len) {
                    int r = stream.Read(buf, l, (int) len - l);
                    if (r == 0) {
                        throw new EndOfStreamException();
                    }
                    l += r;
                }

                value = encoding.GetString(buf);
            }


            public static void WritePrimitive(this Stream stream, byte[] value)
            {
                if (value == null) {
                    WritePrimitive(stream, (uint) 0);
                    return;
                }

                WritePrimitive(stream, (uint) value.Length + 1);
                stream.Write(value, 0, value.Length);
            }

            public static void WritePrimitive(this Stream stream, byte[] value, int offset, int count)
            {
                if (value == null) {
                    WritePrimitive(stream, (uint) 0);
                    return;
                }

                WritePrimitive(stream, (uint) count + 1);
                stream.Write(value, offset, count);
            }

            public static void WritePrimitiveMeta(this Stream stream, byte[] value, bool negative)
            {
                stream.WritePrimitiveMeta(value, 0, value.Length, negative);
            }

            /// <summary>
            ///     Writes a length-encoded byte array with additional
            ///     boolean property stored in sign of length prefix.
            /// </summary>
            /// <param name="stream">Stream to write to.</param>
            /// <param name="value">Source byte array.</param>
            /// <param name="offset">Offset at which to start writing bytes from the source array.</param>
            /// <param name="count">Number of bytes to be written.</param>
            /// <param name="negative">If set to <c>true</c> length-specifying integer will be stored with negative sign.</param>
            public static void WritePrimitiveMeta(this Stream stream, byte[] value, int offset, int count,
                bool negative)
            {
                if (value == null) {
                    WritePrimitive(stream, 0);
                    return;
                }

                WritePrimitive(stream, negative ? -(count + 1) : count + 1);
                stream.Write(value, offset, count);
            }

            private static readonly byte[] EmptyByteArray = new byte[0];

            public static void ReadPrimitive(this Stream stream, out byte[] value)
            {
                uint len;
                ReadPrimitive(stream, out len);

                switch (len) {
                    case 0:
                        value = null;
                        return;
                    case 1:
                        value = EmptyByteArray;
                        return;
                }

                len -= 1;

                value = new byte[len];
                int l = 0;

                while (l < len) {
                    int r = stream.Read(value, l, (int) len - l);
                    if (r == 0) {
                        throw new EndOfStreamException();
                    }
                    l += r;
                }
            }

            /// <summary>
            ///     Reads a length-encoded byte array with additional boolean property stored as integer sign.
            /// </summary>
            /// <param name="stream">Stream to be read from.</param>
            /// <param name="value">Output byte array.</param>
            /// <param name="negative">Stored boolean state. Will be <c>true</c> if stored integer has negative sign.</param>
            public static void ReadPrimitiveMeta(this Stream stream, out byte[] value, out bool negative)
            {
                int len;
                ReadPrimitive(stream, out len);

                negative = Math.Sign(len) < 0;
                len = Math.Abs(len);

                switch (len) {
                    case 0:
                        value = null;
                        return;
                    case 1:
                        value = EmptyByteArray;
                        return;
                }

                len -= 1;

                value = new byte[len];
                int l = 0;

                while (l < len) {
                    int r = stream.Read(value, l, len - l);
                    if (r == 0) {
                        throw new EndOfStreamException();
                    }
                    l += r;
                }
            }

            /// <summary>
            ///     Reads an enumeration value from a stream that was encoded as a string.
            /// </summary>
            /// <typeparam name='T'>
            ///     Must be an enumeration type.
            /// </typeparam>
            public static void ReadPrimitive<T>(this Stream stream, out T value) where T : struct, IConvertible
            {
                if (!typeof (T).IsEnum) {
                    throw new InvalidOperationException("T must be an enumerated type.");
                }
                try {
                    string stringValue;
                    ReadPrimitive(stream, out stringValue);
                    value = (T) Enum.Parse(typeof (T), stringValue);
                } catch (ArgumentException) {
                    throw new ArgumentException("Enumeration member is unknown or otherwise invalid.");
                }
            }

            /// <summary>
            ///     Writes an enumeration value into a stream, encoded as a string .
            /// </summary>
            /// <typeparam name='T'>
            ///     Must be an enumeration type.
            /// </typeparam>
            public static void WritePrimitive<T>(this Stream stream, T value) where T : struct, IConvertible
            {
                if (!typeof (T).IsEnum) {
                    throw new InvalidOperationException("T must be an enumerated type.");
                }

                WritePrimitive(stream, Enum.GetName(typeof (T), value));
            }

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
}
