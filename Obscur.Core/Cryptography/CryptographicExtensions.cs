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
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;

namespace Obscur.Core.Cryptography
{
    /// <summary>
    /// Extension methods for cryptographic use.
    /// </summary>
    public static class CryptographicExtensions
    {
        #region Equality checking for arrays

        public static bool SequenceEqualConstantTime<T>(this T[] a, T[] b, bool lengthMustMatch = false) where T : struct
        {
            if (a == null && b == null) {
                return true;
            }

            if (a == null) {
                throw new ArgumentNullException("a");
            } else if (b == null) {
                throw new ArgumentNullException("b");
            }

            int i = a.Length;
            if (lengthMustMatch && i != b.Length) {
                return false;
            }

            bool equal = true;
            while (i != 0) {
                --i;
                if (!a[i].Equals(b[i])) {
                    equal = false;
                }
            }
            return equal;
        }

        /// <summary>
        ///     A constant time equals comparison - DOES NOT terminate early if
        ///     test will fail.
        ///     Checks as far as <paramref name="a"/> is in length by default (<paramref name="lengthMustMatch"/> is false).
        /// </summary>
        /// <param name="a">Array to compare against.</param>
        /// <param name="b">Array to test for equality.</param>
        /// <returns>If <c>true</c>, array section tested is equal.</returns>
        public static bool SequenceEqualConstantTime(this byte[] a, byte[] b, bool lengthMustMatch = false)
        {
            if (a == null && b == null) {
                return true;
            }
            if (a == null) {
                throw new ArgumentNullException("a");
            } else if (b == null) {
                throw new ArgumentNullException("b");
            }
            int aLen = a.Length;
            if (lengthMustMatch && aLen != b.Length) {
                return false;
            }

            return a.SequenceEqualConstantTime(0, b, 0, a.Length);
        }

        /// <summary>
        ///     A constant time equals comparison - DOES NOT terminate early if
        ///     test will fail.
        /// </summary>
        /// <param name="a">Array to compare against.</param>
        /// <param name="aOffset">Index in <paramref name="a"/> to start comparison at.</param>
        /// <param name="b">Array to test for equality.</param>
        /// <param name="bOffset">Index in <paramref name="b"/> to start comparison at.</param>
        /// <param name="length">Number of bytes to compare.</param>
        /// <returns>If <c>true</c>, array section tested is equal.</returns>
        public static bool SequenceEqualConstantTime(this byte[] a, int aOffset, byte[] b, int bOffset, int length)
        {
            if (a == null && b == null) {
                return true;
            }
            if (a == null) {
                throw new ArgumentNullException("a");
            }
            if (aOffset < 0) {
                throw new ArgumentOutOfRangeException("aOffset", "aOffset < 0");
            }
            if (b == null) {
                throw new ArgumentNullException("b");
            }
            if (bOffset < 0) {
                throw new ArgumentOutOfRangeException("bOffset", "bOffset < 0");
            }
            if (length < 0) {
                throw new ArgumentOutOfRangeException("length", "length < 0");
            }
            if ((uint)aOffset + (uint)length > (uint)a.Length) {
                throw new ArgumentOutOfRangeException("length", "aOffset + length > a.Length");
            }
            if ((uint)bOffset + (uint)length > (uint)b.Length) {
                throw new ArgumentOutOfRangeException("length", "bOffset + length > b.Length");
            }

            return SequenceEqualConstantTime_NoChecks(a, aOffset, b, bOffset, length);
        }

        public static bool SequenceEqualConstantTime_NoChecks(this byte[] a, int aOffset, byte[] b, int bOffset, int length)
        {
            if (a == null && b == null) {
                return true;
            }

#if INCLUDE_UNSAFE
            if (length >= StratCom.UnmanagedThreshold) {
                unsafe {
                    fixed (byte* srcPtr = &a[aOffset]) {
                        fixed (byte* dstPtr = &b[bOffset]) {
                            return ByteArraysEqual_ConstantTime_Internal(srcPtr, dstPtr, length);
                        }
                    }
                }
            } else {
#endif
                int differentbits = 0;
                for (int i = 0; i < length; i++) {
                    differentbits |= a[aOffset + i] ^ b[bOffset + i];
                }
                return (1 & (((uint)differentbits - 1) >> 8)) != 0;
#if INCLUDE_UNSAFE
            }
#endif
        }

        public static bool SequenceEqualVariableTime<T>(this T[] a, T[] b, bool lengthMustMatch = false) where T : struct
        {
            if (a == null && b == null) {
                return true;
            }

            if (a == null) {
                throw new ArgumentNullException("a");
            } else if (b == null) {
                throw new ArgumentNullException("b");
            }

            int i = a.Length;
            if (lengthMustMatch && i != b.Length) {
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
        ///     A variable time equals comparison - DOES terminate early if
        ///     test will fail.
        ///     Checks as far as <paramref name="a"/> is in length by default (<paramref name="lengthMustMatch"/> is false).
        /// </summary>
        /// <param name="a">Array to compare against.</param>
        /// <param name="b">Array to test for equality.</param>
        /// <returns>If <c>true</c>, array section tested is equal.</returns>
        public static bool SequenceEqualVariableTime(this byte[] a, byte[] b, bool lengthMustMatch = false)
        {
            if (a == null && b == null) {
                return true;
            }
            if (a == null) {
                throw new ArgumentNullException("a");
            } else if (b == null) {
                throw new ArgumentNullException("b");
            }
            int aLen = a.Length;
            if (lengthMustMatch && aLen != b.Length) {
                return false;
            }

            return a.SequenceEqualVariableTime(0, b, 0, a.Length);
        }

        /// <summary>
        ///     A variable time equals comparison - DOES terminate early if test will fail.
        /// </summary>
        /// <param name="a">Array to compare against.</param>
        /// <param name="aOffset">Index in <paramref name="a"/> to start comparison at.</param>
        /// <param name="b">Array to test for equality.</param>
        /// <param name="bOffset">Index in <paramref name="b"/> to start comparison at.</param>
        /// <param name="length">Number of bytes to compare.</param>
        /// <returns>If <c>true</c>, array section tested is equal.</returns>
        public static bool SequenceEqualVariableTime(this byte[] a, int aOffset, byte[] b, int bOffset, int length)
        {
            if (a == null && b == null) {
                return true;
            }
            if (a == null) {
                throw new ArgumentNullException("a");
            }
            if (aOffset < 0) {
                throw new ArgumentOutOfRangeException("aOffset", "aOffset < 0");
            }
            if (b == null) {
                throw new ArgumentNullException("b");
            }
            if (bOffset < 0) {
                throw new ArgumentOutOfRangeException("bOffset", "bOffset < 0");
            }
            if (length < 0) {
                throw new ArgumentOutOfRangeException("length", "length < 0");
            }
            if ((uint)aOffset + (uint)length > (uint)a.Length) {
                throw new ArgumentOutOfRangeException("length", "aOffset + length > a.Length");
            }
            if ((uint)bOffset + (uint)length > (uint)b.Length) {
                throw new ArgumentOutOfRangeException("length", "bOffset + length > b.Length");
            }

            return SequenceEqualVariableTime_NoChecks(a, aOffset, b, bOffset, length);
        }

        public static bool SequenceEqualVariableTime_NoChecks(this byte[] a, int aOffset, byte[] b, int bOffset, int length)
        {
            if (a == null && b == null) {
                return true;
            }

#if INCLUDE_UNSAFE
            if (length >= StratCom.UnmanagedThreshold) {
                unsafe {
                    fixed (byte* srcPtr = &a[aOffset]) {
                        fixed (byte* dstPtr = &b[bOffset]) {
                            return ByteArraysEqual_ConstantTime_Internal(srcPtr, dstPtr, length);
                        }
                    }
                }
            } else {
#endif

                int i = a.Length;
                while (i != 0) {
                    --i;
                    if (!a[i].Equals(b[i])) {
                        return false;
                    }
                }
                return true;
#if INCLUDE_UNSAFE
            }
#endif
        }

#if INCLUDE_UNSAFE

        internal static unsafe bool ByteArraysEqual_ConstantTime_Internal(byte* aPtr, byte* bPtr, int length)
        {
            const int u32Size = sizeof(UInt32);
            const int u64Size = sizeof(UInt64);

            byte* aEndPtr = aPtr + length;
            UInt32 differentBits8 = 0u;
            UInt32 differentBits32 = 0u;
            UInt64 differentBits64 = 0ul;

            if (StratCom.PlatformWordSize == u32Size) {
                while (aPtr + u64Size <= aEndPtr) {
                    differentBits32 |= *(UInt32*)aPtr ^ *(UInt32*)bPtr;
                    aPtr += u32Size;
                    bPtr += u32Size;
                    differentBits32 |= *(UInt32*)aPtr ^ *(UInt32*)bPtr;
                    aPtr += u32Size;
                    bPtr += u32Size;
                }
            } else if (StratCom.PlatformWordSize == u64Size) {
                const int u128Size = u64Size * 2;
                while (aPtr + u128Size <= aEndPtr) {
                    differentBits64 |= *(UInt64*)aPtr ^ *(UInt64*)bPtr;
                    aPtr += u64Size;
                    bPtr += u64Size;
                    differentBits64 |= *(UInt64*)aPtr ^ *(UInt64*)bPtr;
                    aPtr += u64Size;
                    bPtr += u64Size;
                }
                if (aPtr + u64Size <= aEndPtr) {
                    differentBits64 |= *(UInt64*)aPtr ^ *(UInt64*)bPtr;
                    aPtr += u64Size;
                    bPtr += u64Size;
                }
            }
            if (StratCom.PlatformWordSize == u32Size && aPtr + u32Size <= aEndPtr) {
                differentBits32 |= *(UInt32*)aPtr ^ *(UInt32*)bPtr;
                aPtr += u32Size;
                bPtr += u32Size;
            }
            // Process remainder (shorter than native word size) as individual bytes
            while (aPtr + 1 <= aEndPtr) {
                differentBits8 |= (UInt32)(*aPtr++ ^ *bPtr++);
            }

            // Assess for differences
            bool diff8 = (1 & ((differentBits8 - 1) >> 8)) != 0;
            if (StratCom.PlatformWordSize == u32Size) {
                bool diff32 = (1 & ((differentBits32 - 1) >> 32)) != 0;
                return diff8 | diff32;
            } else if (StratCom.PlatformWordSize == u64Size) {
                bool diff64 = (1 & ((differentBits64 - 1) >> 64)) != 0;
                return diff8 | diff64;
            }
            throw new NotSupportedException("ISA from the future or the past being used - this code doesn't support native word sizes other than 32 or 64 bits!");
        }

        internal static unsafe bool ByteArraysEqual_VariableTime_Internal(byte* aPtr, byte* bPtr, int length)
        {
            const int u32Size = sizeof(UInt32);
            const int u64Size = sizeof(UInt64);

            byte* aEndPtr = aPtr + length;
            UInt32 differentBits32 = 0u;
            UInt64 differentBits64 = 0ul;

            if (StratCom.PlatformWordSize == u32Size) {
                while (aPtr + u64Size <= aEndPtr) {
                    differentBits32 |= *(UInt32*)aPtr ^ *(UInt32*)bPtr;
                    aPtr += u32Size;
                    bPtr += u32Size;
                    differentBits32 |= *(UInt32*)aPtr ^ *(UInt32*)bPtr;
                    aPtr += u32Size;
                    bPtr += u32Size;
                    if (differentBits32 != 0u)
                        return false;
                }
            } else if (StratCom.PlatformWordSize == u64Size) {
                const int u128Size = u64Size * 2;
                while (aPtr + u128Size <= aEndPtr) {
                    differentBits64 |= *(UInt64*)aPtr ^ *(UInt64*)bPtr;
                    aPtr += u64Size;
                    bPtr += u64Size;
                    differentBits64 |= *(UInt64*)aPtr ^ *(UInt64*)bPtr;
                    aPtr += u64Size;
                    bPtr += u64Size;
                }
                if (differentBits64 != 0ul)
                    return false;
                if (aPtr + u64Size <= aEndPtr) {
                    if (*(UInt64*)aPtr != *(UInt64*)bPtr) {
                        return false;
                    }
                    aPtr += u64Size;
                    bPtr += u64Size;
                }
            }
            if (StratCom.PlatformWordSize == u32Size && aPtr + u32Size <= aEndPtr) {
                if (*(UInt32*)aPtr != *(UInt32*)bPtr) {
                    return false;
                }
                aPtr += u32Size;
                bPtr += u32Size;
            }
            if (aPtr + sizeof(UInt16) <= aEndPtr) {
                if (*(UInt16*)aPtr != *(UInt16*)bPtr) {
                    return false;
                }
                aPtr += sizeof(UInt16);
                bPtr += sizeof(UInt16);
            }
            if (aPtr + 1 <= aEndPtr) {
                return *aPtr == *bPtr;
            }
            return true;
        }

#endif
        
        #endregion

        #region XOR for arrays

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
            const int u32Size = sizeof(UInt32);
            const int u64Size = sizeof(UInt64);

            byte* outputEnd = output + length;
            
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
            } else if (StratCom.PlatformWordSize == u64Size) {
                // 64-bit
                const int u128Size = u64Size * 2;
                while (output + u128Size <= outputEnd) {
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
            const int u64Size = sizeof(UInt64);

            byte* aEnd = a + length;

            if (StratCom.PlatformWordSize == u32Size) {
                // 32-bit
                while (a + u64Size <= aEnd) {
                    *(UInt32*) a ^= *(UInt32*) b;
                    a += u32Size;
                    b += u32Size;
                    *(UInt32*) a ^= *(UInt32*) b;
                    a += u32Size;
                    b += u32Size;
                }
            } else if (StratCom.PlatformWordSize == u64Size) {
                // 64-bit
                const int u128Size = u64Size * 2;
                while (a + u128Size <= aEnd) {
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

        #endregion

        #region Secure erase memory

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

        internal static unsafe void WipeMemory(byte* targetPtr, int length)
        {
            const int u32Size = sizeof(UInt32);
            const int u64Size = sizeof(UInt64);

            byte* targetEndPtr = targetPtr + length;

            if (StratCom.PlatformWordSize == u32Size) {               
                while (targetPtr + u64Size <= targetEndPtr) {
                    *(UInt32*)targetPtr = 0u;
                    targetPtr += u32Size;
                    *(UInt32*)targetPtr = 0u;
                    targetPtr += u32Size;
                }
            } else if (StratCom.PlatformWordSize == u64Size) {
                const int u128Size = u64Size * 2;
                while (targetPtr + u128Size <= targetEndPtr) {
                    *(UInt64*)targetPtr = 0ul;
                    targetPtr += u64Size;
                    *(UInt64*)targetPtr = 0ul;
                    targetPtr += u64Size;
                }
                if (targetPtr + u64Size <= targetEndPtr) {
                    *(UInt64*)targetPtr = 0ul;
                    targetPtr += u64Size;
                }
            }
            if (targetPtr + u32Size <= targetEndPtr) {
                *(UInt32*) targetPtr = 0u;
                targetPtr += u32Size;
            }
            if (targetPtr + sizeof(UInt16) <= targetEndPtr) {
                *(UInt16*)targetPtr = 0;
                targetPtr += sizeof(UInt16);
            }
            if (targetPtr <= targetEndPtr) {
                *targetPtr = (byte)0;
            }
        }

        internal static unsafe void SetMemory(byte* targetPtr, byte val, int length)
        {
            const int u32Size = sizeof(UInt32);
            const int u64Size = sizeof(UInt64);

            byte* targetEndPtr = targetPtr + length;
            byte* val64 = stackalloc byte[u64Size];
            for (int i = 0; i < u64Size; i++) {
                val64[i] = val;
            }
            
            if (StratCom.PlatformWordSize == u32Size) {
                while (targetPtr + u64Size <= targetEndPtr) {
                    *(UInt32*)targetPtr = *(UInt32*)val64;
                    targetPtr += u32Size;
                    *(UInt32*)targetPtr = *(UInt32*)val64;
                    targetPtr += u32Size;
                }
            } else if (StratCom.PlatformWordSize == u64Size) {
                const int u128Size = u64Size * 2;
                while (targetPtr + u128Size <= targetEndPtr) {
                    *(UInt64*)targetPtr = *val64;
                    targetPtr += u64Size;
                    *(UInt64*)targetPtr = *val64;
                    targetPtr += u64Size;
                }
                if (targetPtr + u64Size <= targetEndPtr) {
                    *(UInt64*)targetPtr = *val64;
                    targetPtr += u64Size;
                }
            }

            if (targetPtr + u32Size <= targetEndPtr) {
                *(UInt32*)targetPtr = *(UInt32*)val64;
                targetPtr += u32Size;
            }

            if (targetPtr + sizeof(UInt16) <= targetEndPtr) {
                *(UInt16*)targetPtr = *(UInt16*)val64;
                targetPtr += sizeof(UInt16);
            }

            if (targetPtr <= targetEndPtr) {
                *targetPtr = val;
            }
        }
#endif

        #endregion
    }
}
