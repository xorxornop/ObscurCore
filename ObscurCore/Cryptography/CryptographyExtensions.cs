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
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;

namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Extension methods for cryptographic use.
    /// </summary>
    public static class CryptographyExtensions
    {
        /// <summary>
        ///     A constant time equals comparison - does not terminate early if
        ///     test will fail.
        ///     Checks as far as <paramref name="a"/> is in length.
        /// </summary>
        /// <param name="a">Array to compare against.</param>
        /// <param name="b">Array to test for equality.</param>
        /// <returns>If <c>true</c>, array section tested is equal.</returns>
        public static bool SequenceEqual_ConstantTime(this byte[] a, byte[] b)
        {
            return a.SequenceEqual_ConstantTime(0, b, 0, a.Length);
        }

        /// <summary>
        ///     A constant time equals comparison - does not terminate early if
        ///     test will fail.
        /// </summary>
        /// <param name="x">Array to compare against.</param>
        /// <param name="xOffset">Index in <paramref name="x"/> to start comparison at.</param>
        /// <param name="y">Array to test for equality.</param>
        /// <param name="yOffset">Index in <paramref name="y"/> to start comparison at.</param>
        /// <param name="length">Number of bytes to compare.</param>
        /// <returns>If <c>true</c>, array section tested is equal.</returns>
        public static bool SequenceEqual_ConstantTime(this byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
            if (x == null && y == null) {
                return true;
            }
            if (x == null) {
                throw new ArgumentNullException("x");
            }
            if (xOffset < 0) {
                throw new ArgumentOutOfRangeException("xOffset", "xOffset < 0");
            }
            if (y == null) {
                throw new ArgumentNullException("y");
            }
            if (yOffset < 0) {
                throw new ArgumentOutOfRangeException("yOffset", "yOffset < 0");
            }
            if (length < 0) {
                throw new ArgumentOutOfRangeException("length", "length < 0");
            }
            if ((uint) xOffset + (uint) length > (uint) x.Length) {
                throw new ArgumentOutOfRangeException("length", "xOffset + length > x.Length");
            }
            if ((uint) yOffset + (uint) length > (uint) y.Length) {
                throw new ArgumentOutOfRangeException("length", "yOffset + length > y.Length");
            }

            return SequenceEqual_ConstantTime_NoChecks(x, xOffset, y, yOffset, length);
        }

        // From CodesInChaos
        private static bool SequenceEqual_ConstantTime_NoChecks(byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
            int differentbits = 0;
            for (int i = 0; i < length; i++) {
                differentbits |= x[xOffset + i] ^ y[yOffset + i];
            }
            return (1 & (((uint) differentbits - 1) >> 8)) != 0;
        }

        /// <summary>
        ///     XOR byte arrays <paramref name="a"/> and <paramref name="b"/> together into <paramref name="output"/>.
        /// </summary>
        /// <param name="a">Source #0 array.</param>
        /// <param name="aOff">Source array #0 offset.</param>
        /// <param name="b">Source #1 array.</param>
        /// <param name="bOff">Source #1 array offset.</param>
        /// <param name="output">Output array.</param>
        /// <param name="outputOff">Output array offset.</param>
        /// <param name="length">Length to XOR.</param>
        public static void Xor(this byte[] a, int aOff, byte[] b, int bOff, byte[] output, int outputOff, int length)
        {
            if (length <= 0) {
                throw new ArgumentException("Length is not positive.", "length");
            }
            if (a == null) {
                throw new ArgumentNullException("a");
            }
            if (aOff < 0) {
                throw new ArgumentOutOfRangeException("aOff", "aOff must be 0 or positive.");
            }
            if (aOff + length > a.Length) {
                throw new ArgumentException("Insufficient length.", "a");
            }
            if (b == null) {
                throw new ArgumentNullException("b");
            }
            if (bOff < 0) {
                throw new ArgumentOutOfRangeException("bOff", "bOff must be 0 or positive.");
            }
            if (bOff + length > b.Length) {
                throw new ArgumentException("Insufficient length.", "b");
            }
            if (output == null) {
                throw new ArgumentNullException("output");
            }
            if (outputOff < 0) {
                throw new ArgumentOutOfRangeException("outputOff", "outputOff must be 0 or positive.");
            }
            if (outputOff + length > output.Length) {
                throw new DataLengthException("Insufficient length.", "output");
            }

            XorInternal(a, aOff, b, bOff, output, outputOff, length);
        }

        private const int XorUnmanagedLengthThreshold = 128;

        internal static void XorInternal(this byte[] a, int aOff, byte[] b, int bOff, byte[] output, int outputOff,
            int length)
        {
#if (INCLUDE_UNSAFE)
            if (length > XorUnmanagedLengthThreshold) {
                unsafe {
                    fixed (byte* aPtr = a) {
                        fixed (byte* bPtr = b) {
                            fixed (byte* outPtr = output) {
                                XorMemory(aPtr + aOff, bPtr + bOff, outPtr + outputOff, length);
                            }
                            
                        }
                    }
                }
            }
#endif
            for (var i = 0; i < length; i++) {
                output[outputOff + i] = (byte) (a[aOff + i] ^ b[bOff + i]);
            }
        }

        /// <summary>
        ///     XOR the specified byte array <paramref name="b"/> into <paramref name="a"/> in-place.
        /// </summary>
        /// <param name="a">Destination and source #0 array.</param>
        /// <param name="aOff">Destination and source array #0 offset.</param>
        /// <param name="b">Source #1 array.</param>
        /// <param name="bOff">Source #1 array offset.</param>
        /// <param name="length">Length to XOR.</param>
        public static void XorInPlace(this byte[] a, int aOff, byte[] b, int bOff, int length)
        {
            if (length <= 0) {
                throw new ArgumentException("Length is not positive.", "length");
            }
            if (aOff < 0) {
                throw new ArgumentOutOfRangeException("aOff", "aOff must be 0 or positive.");
            }
            if (aOff + length > a.Length) {
                throw new ArgumentException("Insufficient length.", "a");
            }
            if (bOff < 0) {
                throw new ArgumentOutOfRangeException("bOff", "bOff must be 0 or positive.");
            }
            if (bOff + length > b.Length) {
                throw new ArgumentException("Insufficient length.", "b");
            }

            XorInPlaceInternal(a, aOff, b, bOff, length);
        }

        internal static void XorInPlaceInternal(this byte[] a, int aOff, byte[] b, int bOff, int length)
        {
#if (INCLUDE_UNSAFE)
            if (length > XorUnmanagedLengthThreshold) {
                unsafe {
                    fixed (byte* aPtr = a) {
                        fixed (byte* bPtr = b) {
                            XorMemoryInPlace(aPtr + aOff, bPtr + bOff, length);
                        }
                    }
                }
            }
#endif
            for (var i = 0; i < length; i++) {
                a[aOff + i] ^= b[bOff + i];
            }
        }
#if INCLUDE_UNSAFE
        internal static unsafe void XorMemory(byte* a, byte* b, byte* output, int length)
        {
            byte* outputEnd = output + length;
            const int u32Size = sizeof(UInt32);
            if (StratCom.PlatformWordSize == u32Size) {
                // 32-bit
                while (output + (u32Size * 2) <= outputEnd) {
                    *(UInt32*)output = *(UInt32*)a ^ *(UInt32*)b;
                    a += u32Size;
                    b += u32Size;
                    output += u32Size;
                    *(UInt32*)output = *(UInt32*)a ^ *(UInt32*)b;
                    a += u32Size;
                    b += u32Size;
                    output += u32Size;
                }
            } else if (StratCom.PlatformWordSize == sizeof(UInt64)) {
                // 64-bit
                const int u64Size = sizeof(UInt64);
                while (output + (u64Size * 2) <= outputEnd) {
                    *(UInt32*)output = *(UInt32*)a ^ *(UInt32*)b;
                    a += u64Size;
                    b += u64Size;
                    output += u64Size;
                    *(UInt32*)output = *(UInt32*)a ^ *(UInt32*)b;
                    a += u64Size;
                    b += u64Size;
                    output += u64Size;
                }
                if (output + u64Size <= outputEnd) {
                    *(UInt64*) output = *(UInt64*) a ^ *(UInt64*) b;
                    a += u64Size;
                    b += u64Size;
                    output += u64Size;
                }
            }

            if (output + u32Size <= outputEnd) {
                *(UInt32*)output = *(UInt32*)a ^ *(UInt32*)b;
                a += u32Size;
                b += u32Size;
                output += u32Size;
            }

            if (output + sizeof(UInt16) <= outputEnd) {
                *(UInt16*)output = (UInt16)(*(UInt16*)a ^ *(UInt16*)b);
                a += sizeof(UInt16);
                b += sizeof(UInt16);
                output += sizeof(UInt16);
            }

            if (output + 1 <= outputEnd) {
                *output = (byte)(*a ^ *b);
            }
        }

        /// <summary>
        ///      XOR the specified data in <paramref name="b"/> into <paramref name="a"/> in-place.
        /// </summary>
        /// <param name="a">Pointer to source of and destination for data.</param>
        /// <param name="b">Pointer to source of data.</param>
        /// <param name="length">Length of data to copy in bytes.</param>
        internal static unsafe void XorMemoryInPlace(byte* a, byte* b, int length)
        {
            const int u32Size = sizeof(UInt32);
            byte* aEnd = a + length;
            if (StratCom.PlatformWordSize == u32Size) {
                // 32-bit
                while (a + u32Size * 2 <= aEnd) {
                    *(UInt32*) a ^= *(UInt32*) b;
                    a += u32Size;
                    b += u32Size;
                    *(UInt32*) a ^= *(UInt32*) b;
                    a += u32Size;
                    b += u32Size;
                }
            } else if (StratCom.PlatformWordSize == sizeof(UInt64)) {
                // 64-bit
                const int u64Size = sizeof(UInt64);
                while (a + u64Size * 2 <= aEnd) {
                    *(UInt64*) a ^= *(UInt64*) b;
                    a += u64Size;
                    b += u64Size;
                    *(UInt64*) a ^= *(UInt64*) b;
                    a += u64Size;
                    b += u64Size;
                }
                if (a + u64Size <= aEnd) {
                    *(UInt64*) a ^= *(UInt64*) b;
                    a += u64Size;
                    b += u64Size;
                }
            }

            if (a + u32Size <= aEnd) {
                *(UInt32*)a ^= *(UInt32*)b;
                a += u32Size;
                b += u32Size;
            }

            if (a + sizeof(UInt16) >= aEnd) {
                *(UInt16*)a ^= *(UInt16*)b;
                a += sizeof(UInt16);
                b += sizeof(UInt16);
            }

            if (a + 1 <= aEnd) {
                *a ^= *b;
            }
        }
#endif


        /// <summary>
        ///     Securely erase <paramref name="data"/> by clearing the memory used to store it.
        /// </summary>
        /// <param name="data">Data to erase.</param>
        public static void SecureWipe<T>(this T[] data) where T : struct
        {
            if (data == null) {
                throw new ArgumentNullException("data");
            }

            InternalWipe(data, 0, data.Length);
        }

        /// <summary>
        ///     Securely erase <paramref name="data"/> by clearing the memory used to store it.
        /// </summary>
        /// <param name="data">Data to erase.</param>
        /// <param name="offset">Offset in <paramref name="data"/> to erase from.</param>
        /// <param name="count">Number of elements to erase.</param>
        public static void SecureWipe<T>(this T[] data, int offset, int count) where T : struct
        {
            Contract.Requires<ArgumentNullException>(data != null);
            Contract.Requires<ArgumentOutOfRangeException>(offset >= 0);
            Contract.Requires<ArgumentOutOfRangeException>(count > 0);

            Contract.Ensures(offset + count <= data.Length);

            InternalWipe(data, offset, count);
        }

        /// <summary>
        ///     Securely erase <paramref name="data"/> by clearing the memory used to store it.
        /// </summary>
        /// <param name="data">Data to erase.</param>
        public static void SecureWipe(this byte[] data)
        {
            Contract.Requires<ArgumentNullException>(data != null);

            InternalWipe(data, 0, data.Length);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void InternalWipe<T>(T[] data, int offset, int count) where T : struct
        {
            Array.Clear(data, offset, count);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void InternalWipe(byte[] data, int offset, int count)
        {
#if INCLUDE_UNSAFE
            unsafe {
                fixed (byte* ptr = data) {
                    WipeMemory(ptr + offset, count);
                }
            }
#else
            Array.Clear(data, offset, count);
#endif
        }

#if INCLUDE_UNSAFE
        internal static unsafe void WipeMemory(ushort* src, int length)
        {
            WipeMemory((byte*)src, sizeof(ushort) * length);
        }

        internal static unsafe void WipeMemory(uint* src, int length)
        {
            WipeMemory((byte*)src, sizeof(uint) * length);
        }

        internal static unsafe void WipeMemory(ulong* src, int length)
        {
            WipeMemory((byte*)src, sizeof(ulong) * length);
        }

        internal static unsafe void WipeMemory(byte* src, int length)
        {
            const int u32Size = sizeof(UInt32);
            if (StratCom.PlatformWordSize == u32Size) {               
                while (length >= u32Size * 2) {
                    *(UInt32*)src = 0u;
                    src += u32Size;
                    *(UInt32*)src = 0u;
                    src += u32Size;
                    length -= u32Size * 2;
                }
            } else if (StratCom.PlatformWordSize == sizeof(UInt64)) {
                const int u64Size = sizeof(UInt64);
                while (length >= u64Size * 2) {
                    *(UInt64*)src = 0ul;
                    src += u64Size;
                    *(UInt64*)src = 0ul;
                    src += u64Size;
                    length -= u64Size * 2;
                }
                if (length >= u64Size) {
                    *(UInt64*)src = 0ul;
                    src += u64Size;
                    length -= u64Size;
                }
            }
            if (length >= u32Size) {
                *(UInt32*) src = 0u;
                src += u32Size;
                length -= u32Size;
            }
            if (length >= sizeof(UInt16)) {
                *(UInt16*)src = (UInt16)0u;
                src += sizeof(UInt16);
                length -= sizeof(UInt16);
            }
            if (length > 0) {
                *src = (byte)0;
            }
        }

        internal static unsafe void SetMemory(byte* src, byte val, int length)
        {
            byte* val64 = stackalloc byte[sizeof(UInt64)];
            for (int i = 0; i < sizeof(UInt64); i++) {
                val64[i] = val;
            }

            if (StratCom.PlatformWordSize == sizeof(UInt32)) {
                while (length >= sizeof(UInt64)) {
                    *(UInt32*)src = *(UInt32*)val64;
                    src += sizeof(UInt32);
                    *(UInt32*)src = *(UInt32*)val64;
                    src += sizeof(UInt32);
                    length -= sizeof(UInt64);
                }
            } else if (StratCom.PlatformWordSize == sizeof(UInt64)) {
                while (length >= sizeof(UInt64) * 2) {
                    *(UInt64*)src = *val64;
                    src += sizeof(UInt64);
                    *(UInt64*)src = *val64;
                    src += sizeof(UInt64);
                    length -= sizeof(UInt64) * 2;
                }

                if (length >= sizeof(UInt64)) {
                    *(UInt64*)src = *val64;
                    src += sizeof(UInt64);
                    length -= sizeof(UInt64);
                }
            }

            if (length >= sizeof(UInt32)) {
                *(UInt32*)src = *(UInt32*)val64;
                src += sizeof(UInt32);
                length -= sizeof(UInt32);
            }

            if (length >= sizeof(UInt16)) {
                *(UInt16*)src = *(UInt16*)val64;
                src += sizeof(UInt16);
                length -= sizeof(UInt16);
            }

            if (length > 0) {
                *src = val;
            }
        }
#endif
    }
}
