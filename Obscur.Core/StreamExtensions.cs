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
using System.IO;

namespace Obscur.Core
{
    /// <summary>
    /// Extension methods for writing and reading to/from streams.
    /// </summary>
    public static class StreamExtensions
    {
        /// <summary>
        /// Writes a boolean value to a stream as a byte (0 or 1).
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Boolean value to write.</param>
        public static void WriteBoolean(this Stream stream, bool value)
        {
            stream.WriteByte(value ? (byte) 1 : (byte) 0);
        }

        /// <summary>
        /// Reads a boolean value from a stream as a byte (0 or 1).
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static bool ReadBoolean(this Stream stream)
        {
            int b = stream.ReadByte();
            return b != 0;
        }

        /// <summary>
        /// Encode an unsigned integer as a variable-length 
        /// integer and write it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static void WriteUInt16(this Stream stream, UInt16 value)
        {
            WriteVarint32(stream, value);
        }

        /// <summary>
        /// Reads an unsigned integer that was encoded as a 
        /// variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static UInt16 ReadUInt16(this Stream stream)
        {
            return (UInt16)ReadVarint32(stream);
        }

        /// <summary>
        /// Encodes a signed integer as a 'zig-zag' variable-length 
        /// integer and writes it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static void WriteInt16(this Stream stream, Int16 value)
        {
            WriteVarint32(stream, EncodeZigZag32(value));
        }

        /// <summary>
        /// Reads a signed integer that was encoded as a 
        /// 'zig-zag' variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static Int16 ReadInt16(this Stream stream)
        {
            return (Int16)DecodeZigZag32(ReadVarint32(stream));
        }

        /// <summary>
        /// Encodes an unsigned integer as a variable-length 
        /// integer and writes it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static void WriteUInt32(this Stream stream, uint value)
        {
            WriteVarint32(stream, value);
        }

        /// <summary>
        /// Reads an unsigned integer that was encoded as a 
        /// variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static UInt32 ReadUInt32(this Stream stream)
        {
            return ReadVarint32(stream);
        }

        /// <summary>
        /// Encodes a signed integer as a 'zig-zag' variable-length 
        /// integer and writes it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static void WriteInt32(this Stream stream, Int32 value)
        {
            WriteVarint32(stream, EncodeZigZag32(value));
        }

        /// <summary>
        /// Reads a signed integer that was encoded as a 
        /// 'zig-zag' variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static Int32 ReadInt32(this Stream stream)
        {
            return DecodeZigZag32(ReadVarint32(stream));
        }

        /// <summary>
        /// Encodes an unsigned integer as a variable-length 
        /// integer and writes it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static void WriteUInt64(this Stream stream, UInt64 value)
        {
            WriteVarint64(stream, value);
        }

        /// <summary>
        /// Reads an unsigned integer that was encoded as a 
        /// variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static UInt64 ReadUInt64(this Stream stream)
        {
            return ReadVarint64(stream);
        }

        /// <summary>
        /// Encodes a signed integer as a 'zig-zag' variable-length 
        /// integer and writes it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static void WriteInt64(this Stream stream, Int64 value)
        {
            WriteVarint64(stream, EncodeZigZag64(value));
        }

        /// <summary>
        /// Reads a signed integer that was encoded as a 
        /// 'zig-zag' variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static Int64 ReadInt64(this Stream stream)
        {
            return DecodeZigZag64(ReadVarint64(stream));
        }

#if INCLUDE_UNSAFE
        /// <summary>
        /// Encodes a single-precision (32-bit) floating-point number as 
        /// a variable-length integer and writes it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static unsafe void WriteSingle(this Stream stream, Single value)
        {
            UInt32 v = *(UInt32*)(&value);
            WriteVarint32(stream, v);
        }

        /// <summary>
        /// Reads a single-precision (32-bit) floating-point number 
        /// that was encoded as a variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static unsafe Single ReadSingle(this Stream stream)
        {
            UInt32 v = ReadVarint32(stream);
            return *(Single*)(&v);
        }

        /// <summary>
        /// Encodes a double-precision (64-bit) floating-point number as 
        /// a variable-length integer and writes it to a stream.
        /// </summary>
        /// <param name="stream">Stream to write to.</param>
        /// <param name="value">Integer to encode and write.</param>
        public static unsafe void WriteDouble(this Stream stream, Double value)
        {
            UInt64 v = *(UInt64*)(&value);
            WriteVarint64(stream, v);
        }

        /// <summary>
        /// Reads a double-precision (32-bit) floating-point number 
        /// that was encoded as a variable-length integer from a stream.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        public static unsafe Double ReadDouble(this Stream stream)
        {
            UInt64 v = ReadVarint64(stream);
            return *(Double*)(&v);
        }
#endif

        private static UInt32 EncodeZigZag32(Int32 n)
        {
            return (UInt32)((n << 1) ^ (n >> 31));
        }

        private static UInt64 EncodeZigZag64(Int64 n)
        {
            return (UInt64)((n << 1) ^ (n >> 63));
        }

        private static Int32 DecodeZigZag32(UInt32 n)
        {
            return (Int32)(n >> 1) ^ -(Int32)(n & 1);
        }

        private static Int64 DecodeZigZag64(UInt64 n)
        {
            return (Int64)(n >> 1) ^ -(Int64)(n & 1);
        }

        private static UInt32 ReadVarint32(Stream stream)
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
                    return (UInt32)result;
                }
            }

            throw new InvalidDataException();
        }

        private static void WriteVarint32(Stream stream, UInt32 value)
        {
            for (; value >= 0x80u; value >>= 7) {
                stream.WriteByte((byte) (value | 0x80u));
            }

            stream.WriteByte((byte) value);
        }

        private static UInt64 ReadVarint64(Stream stream)
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
                    return (UInt64)result;
                }
            }

            throw new InvalidDataException();
        }

        private static void WriteVarint64(Stream stream, UInt64 value)
        {
            for (; value >= 0x80u; value >>= 7) {
                stream.WriteByte((byte) (value | 0x80u));
            }

            stream.WriteByte((byte) value);
        }
    }
}