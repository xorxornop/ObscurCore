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

namespace ObscurCore
{
    /// <summary>
    ///     Extension methods for packing/unpacking integers into/out of byte arrays.
    /// </summary>
    public static class BitPackingExtensions
    {
        #region Big-endian Int32

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into a byte array
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToBigEndian(this Int32 n)
        {
            var bs = new byte[sizeof (Int32)];
            n.ToBigEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToBigEndian(this Int32 n, byte[] bs)
        {
            bs[0] = (byte) (n >> 24);
            bs[1] = (byte) (n >> 16);
            bs[2] = (byte) (n >> 8);
            bs[3] = (byte) (n);
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToBigEndian(this Int32 n, byte[] bs, int off)
        {
            bs[off + 0] = (byte) (n >> 24);
            bs[off + 1] = (byte) (n >> 16);
            bs[off + 2] = (byte) (n >> 8);
            bs[off + 3] = (byte) (n);
        }

        /// <summary>
        ///     Unpacks a signed integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <returns>32-bit signed integer.</returns>
        public static Int32 BigEndianToInt32(this byte[] bs)
        {
            return bs[0] << 24
                   | bs[1] << 16
                   | bs[2] << 8
                   | bs[3];
        }

        /// <summary>
        ///     Unpacks a signed integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>32-bit signed integer.</returns>
        public static Int32 BigEndianToInt32(this byte[] bs, int off)
        {
            return bs[off] << 24
                   | bs[off + 1] << 16
                   | bs[off + 2] << 8
                   | bs[off + 3];
        }

        #endregion

        #region Big-endian Int64

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into a byte array
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToBigEndian(this Int64 n)
        {
            var bs = new byte[sizeof (Int64)];
            n.ToBigEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToBigEndian(this Int64 n, byte[] bs)
        {
            ((Int32) (n >> 32)).ToBigEndian(bs, 0);
            ((Int32) (n)).ToBigEndian(bs, 4);
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToBigEndian(this Int64 n, byte[] bs, int off)
        {
            ((Int32) (n >> 32)).ToBigEndian(bs, off);
            ((Int32) (n)).ToBigEndian(bs, off + 4);
        }

        /// <summary>
        ///     Unpacks a signed integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <returns>64-bit signed integer.</returns>
        public static Int64 BigEndianToInt64(this byte[] bs)
        {
            Int32 hi = bs.BigEndianToInt32();
            Int32 lo = bs.BigEndianToInt32(4);
            return ((Int64) hi << 32) | lo;
        }

        /// <summary>
        ///     Unpacks a signed integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>64-bit signed integer.</returns>
        public static Int64 BigEndianToInt64(this byte[] bs, int off)
        {
            Int32 hi = bs.BigEndianToInt32(off);
            Int32 lo = bs.BigEndianToInt32(off + 4);
            return ((Int64) hi << 32) | lo;
        }

        #endregion

        #region Big-endian UInt16

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into a byte array
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToBigEndian(this UInt16 n)
        {
            var bs = new byte[sizeof(UInt16)];
            n.ToBigEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToBigEndian(this UInt16 n, byte[] bs)
        {
            bs[0] = (byte)(n >> 8);
            bs[1] = (byte)(n);
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToBigEndian(this UInt16 n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 8);
            bs[off + 1] = (byte)(n);
        }

        /// <summary>
        ///     Unpacks an unsigned integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <returns>16-bit unsigned integer.</returns>
        public static UInt16 BigEndianToUInt16(this byte[] bs)
        {
            uint n = (uint)bs[0] << 8
                     | (uint)bs[1];
            return (ushort)n;
        }

        /// <summary>
        ///     Unpacks an unsigned integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>16-bit unsigned integer.</returns>
        public static UInt16 BigEndianToUInt16(this byte[] bs, int off)
        {
            uint n = (uint)bs[off] << 8
                     | (uint)bs[off + 1];
            return (ushort)n;
        }

        #endregion

        #region Big-endian UInt32

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into a byte array
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToBigEndian(this UInt32 n)
        {
            var bs = new byte[sizeof (UInt32)];
            n.ToBigEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToBigEndian(this UInt32 n, byte[] bs)
        {
            bs[0] = (byte) (n >> 24);
            bs[1] = (byte) (n >> 16);
            bs[2] = (byte) (n >> 8);
            bs[3] = (byte) (n);
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToBigEndian(this UInt32 n, byte[] bs, int off)
        {
            bs[off + 0] = (byte) (n >> 24);
            bs[off + 1] = (byte) (n >> 16);
            bs[off + 2] = (byte) (n >> 8);
            bs[off + 3] = (byte) (n);
        }

        /// <summary>
        ///     Unpacks an unsigned integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <returns>32-bit unsigned integer.</returns>
        public static UInt32 BigEndianToUInt32(this byte[] bs)
        {
            return (UInt32) bs[0] << 24
                   | (UInt32) bs[1] << 16
                   | (UInt32) bs[2] << 8
                   | bs[3];
        }

        /// <summary>
        ///     Unpacks an unsigned integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>32-bit unsigned integer.</returns>
        public static UInt32 BigEndianToUInt32(this byte[] bs, int off)
        {
            return (UInt32) bs[off] << 24
                   | (UInt32) bs[off + 1] << 16
                   | (UInt32) bs[off + 2] << 8
                   | bs[off + 3];
        }

        #endregion

        #region Big-endian UInt64

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into a byte array
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToBigEndian(this UInt64 n)
        {
            var bs = new byte[sizeof (UInt64)];
            n.ToBigEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToBigEndian(this UInt64 n, byte[] bs)
        {
            ((UInt32) (n >> 32)).ToBigEndian(bs, 0);
            ((UInt32) (n)).ToBigEndian(bs, 4);
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in big-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToBigEndian(this UInt64 n, byte[] bs, int off)
        {
            ((UInt32) (n >> 32)).ToBigEndian(bs, off);
            ((UInt32) (n)).ToBigEndian(bs, off + 4);
        }

        /// <summary>
        ///     Unpacks an unsigned integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <returns>64-bit unsigned integer.</returns>
        public static UInt64 BigEndianToUInt64(this byte[] bs)
        {
            UInt32 hi = bs.BigEndianToUInt32();
            UInt32 lo = bs.BigEndianToUInt32(4);
            return ((UInt64) hi << 32) | lo;
        }

        /// <summary>
        ///     Unpacks an unsigned integer in big-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>64-bit unsigned integer.</returns>
        public static UInt64 BigEndianToUInt64(this byte[] bs, int off)
        {
            UInt32 hi = bs.BigEndianToUInt32(off);
            UInt32 lo = bs.BigEndianToUInt32(off + 4);
            return ((UInt64) hi << 32) | lo;
        }

        #endregion

        #region Little-endian Int32

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into a byte array
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToLittleEndian(this Int32 n)
        {
            var bs = new byte[sizeof (Int32)];
            n.ToLittleEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToLittleEndian(this Int32 n, byte[] bs)
        {
            bs[0] = (byte) (n);
            bs[1] = (byte) (n >> 8);
            bs[2] = (byte) (n >> 16);
            bs[3] = (byte) (n >> 24);
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToLittleEndian(this Int32 n, byte[] bs, int off)
        {
            bs[off + 0] = (byte) (n);
            bs[off + 1] = (byte) (n >> 8);
            bs[off + 2] = (byte) (n >> 16);
            bs[off + 3] = (byte) (n >> 24);
        }

        /// <summary>
        ///     Unpacks a signed integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <returns>32-bit signed integer.</returns>
        public static Int32 LittleEndianToInt32(this byte[] bs)
        {
            return bs[0]
                   | bs[1] << 8
                   | bs[2] << 16
                   | bs[3] << 24;
        }

        /// <summary>
        ///     Unpacks a signed integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to read integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>32-bit signed integer.</returns>
        public static Int32 LittleEndianToInt32(this byte[] bs, int off)
        {
            return bs[off]
                   | bs[off + 1] << 8
                   | bs[off + 2] << 16
                   | bs[off + 3] << 24;
        }

        #endregion

        #region Little-endian Int64

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into a byte array
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToLittleEndian(this Int64 n)
        {
            var bs = new byte[sizeof (Int64)];
            n.ToLittleEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToLittleEndian(this Int64 n, byte[] bs)
        {
            ((Int32) n).ToLittleEndian(bs, 0);
            ((Int32) (n >> 32)).ToLittleEndian(bs, 4);
        }

        /// <summary>
        ///     Packs a signed integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToLittleEndian(this Int64 n, byte[] bs, int off)
        {
            ((Int32) n).ToLittleEndian(bs, off);
            ((Int32) (n >> 32)).ToLittleEndian(bs, off + 4);
        }

        /// <summary>
        ///     Unpacks a signed integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <returns>64-bit signed integer.</returns>
        public static Int64 LittleEndianToInt64(this byte[] bs)
        {
            Int32 lo = bs.LittleEndianToInt32(0);
            Int32 hi = bs.LittleEndianToInt32(4);
            return ((Int64) hi << 32) | lo;
        }

        /// <summary>
        ///     Unpacks a signed integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>64-bit signed integer.</returns>
        public static Int64 LittleEndianToInt64(this byte[] bs, int off)
        {
            Int32 lo = bs.LittleEndianToInt32(off);
            Int32 hi = bs.LittleEndianToInt32(off + 4);
            return ((Int64) hi << 32) | lo;
        }

        #endregion

        #region Little-endian UInt16

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into a byte array
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToLittleEndian(this UInt16 n)
        {
            var bs = new byte[sizeof(UInt16)];
            n.ToLittleEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        internal static void ToLittleEndian(this UInt16 n, byte[] bs)
        {
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        internal static void ToLittleEndian(this UInt16 n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
        }

        /// <summary>
        ///     Unpacks an unsigned integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <returns>16-bit unsigned integer.</returns>
        internal static UInt16 LittleEndianToUInt16(this byte[] bs)
        {
            UInt32 n = (UInt32)bs[0]
                     | (UInt32)bs[1] << 8;
            return (UInt16)n;
        }

        /// <summary>
        ///     Unpacks an unsigned integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>16-bit unsigned integer.</returns>
        internal static UInt16 LittleEndianToUInt16(this byte[] bs, int off)
        {
            UInt32 n = (UInt32)bs[off]
                     | (UInt32)bs[off + 1] << 8;
            return (UInt16)n;
        }

        #endregion

        #region Little-endian UInt32

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into a byte array
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToLittleEndian(this UInt32 n)
        {
            var bs = new byte[sizeof (UInt32)];
            n.ToLittleEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToLittleEndian(this UInt32 n, byte[] bs)
        {
            bs[0] = (byte) (n);
            bs[1] = (byte) (n >> 8);
            bs[2] = (byte) (n >> 16);
            bs[3] = (byte) (n >> 24);
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToLittleEndian(this UInt32 n, byte[] bs, int off)
        {
            bs[off + 0] = (byte) (n);
            bs[off + 1] = (byte) (n >> 8);
            bs[off + 2] = (byte) (n >> 16);
            bs[off + 3] = (byte) (n >> 24);
        }

        /// <summary>
        ///     Unpacks an unsigned integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <returns>32-bit unsigned integer.</returns>
        public static UInt32 LittleEndianToUInt32(this byte[] bs)
        {
            return bs[0]
                   | (UInt32) bs[1] << 8
                   | (UInt32) bs[2] << 16
                   | (UInt32) bs[3] << 24;
        }

        /// <summary>
        ///     Unpacks an unsigned integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>32-bit unsigned integer.</returns>
        public static UInt32 LittleEndianToUInt32(this byte[] bs, int off)
        {
            return bs[off]
                   | (UInt32) bs[off + 1] << 8
                   | (UInt32) bs[off + 2] << 16
                   | (UInt32) bs[off + 3] << 24;
        }

        #endregion

        #region Little-endian UInt64

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into a byte array
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <returns>Byte array containing packed integer.</returns>
        public static byte[] ToLittleEndian(this UInt64 n)
        {
            var bs = new byte[sizeof (UInt64)];
            n.ToLittleEndian(bs);
            return bs;
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        public static void ToLittleEndian(this UInt64 n, byte[] bs)
        {
            ((UInt32) n).ToLittleEndian(bs, 0);
            ((UInt32) (n >> 32)).ToLittleEndian(bs, 4);
        }

        /// <summary>
        ///     Packs an unsigned integer <paramref name="n" /> into <paramref name="bs" />
        ///     in little-endian format.
        /// </summary>
        /// <param name="n">Integer to pack.</param>
        /// <param name="bs">Byte array to pack integer into.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to write to.</param>
        public static void ToLittleEndian(this UInt64 n, byte[] bs, int off)
        {
            ((UInt32) n).ToLittleEndian(bs, off);
            ((UInt32) (n >> 32)).ToLittleEndian(bs, off + 4);
        }

        /// <summary>
        ///     Unpacks an unsigned integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <returns>64-bit unsigned integer.</returns>
        public static UInt64 LittleEndianToUInt64(this byte[] bs)
        {
            UInt32 lo = bs.LittleEndianToUInt32(0);
            UInt32 hi = bs.LittleEndianToUInt32(4);
            return ((UInt64) hi << 32) | lo;
        }

        /// <summary>
        ///     Unpacks an unsigned integer in little-endian format from <paramref name="bs" />.
        /// </summary>
        /// <param name="bs">Byte array to unpack integer from.</param>
        /// <param name="off">Offset in <paramref name="bs" /> to read from.</param>
        /// <returns>64-bit unsigned integer.</returns>
        public static UInt64 LittleEndianToUInt64(this byte[] bs, int off)
        {
            UInt32 lo = bs.LittleEndianToUInt32(off);
            UInt32 hi = bs.LittleEndianToUInt32(off + 4);
            return ((UInt64) hi << 32) | lo;
        }

        #endregion
    }
}
