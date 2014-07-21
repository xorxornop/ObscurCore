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
        public static bool SequenceEqualConstantTime(this byte[] a, byte[] b)
        {
            return a.SequenceEqualConstantTime(0, b, 0, a.Length);
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
        public static bool SequenceEqualConstantTime(this byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
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

            return InternalConstantTimeEquals(x, xOffset, y, yOffset, length) != 0;
        }

        // From CodesInChaos
        private static uint InternalConstantTimeEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
            int differentbits = 0;
            for (int i = 0; i < length; i++) {
                differentbits |= x[xOffset + i] ^ y[yOffset + i];
            }
            return (1 & (((uint) differentbits - 1) >> 8));
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
            if (outputOff < 0) {
                throw new ArgumentOutOfRangeException("outputOff", "outputOff must be 0 or positive.");
            }
            if (outputOff + length > output.Length) {
                throw new DataLengthException("Insufficient length.", "output");
            }

            XorInternal(a, aOff, b, bOff, output, outputOff, length);
        }

        internal static void XorInternal(this byte[] a, int aOff, byte[] b, int bOff, byte[] output, int outputOff,
            int length)
        {
#if (INCLUDE_UNSAFE)
			int remainder;
            var ulongOps = Math.DivRem(length, sizeof(ulong), out remainder);
			unsafe {
				fixed (byte* aPtr = a) {
					fixed (byte* bPtr = b) {
						fixed (byte* outputPtr = output) {
                            UInt64* aUlongPtr = (UInt64*)(aPtr + aOff);
                            UInt64* bUlongPtr = (UInt64*)(bPtr + bOff);
                            UInt64* outputUlongPtr = (UInt64*)(outputPtr + outputOff);
							for (var i = 0; i < ulongOps; i++) {
								outputUlongPtr[i] = aUlongPtr[i] ^ bUlongPtr[i];
							}
						}
					}
				}
			}
            var increment = ulongOps * sizeof(UInt64);
            aOff += increment;
			bOff += increment;
			outputOff += increment;
			length = remainder;	
#endif

            for (int i = 0; i < length; i++) {
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
            int remainder;
            var ulongOps = Math.DivRem(length, sizeof(UInt64), out remainder);
			unsafe {
				fixed (byte* aPtr = a) {
					fixed (byte* bPtr = b) {
                        UInt64* aUlongPtr = (UInt64*)(aPtr + aOff);
                        UInt64* bUlongPtr = (UInt64*)(bPtr + bOff);
						for (var i = 0; i < ulongOps; i++) {
							aUlongPtr[i] ^= bUlongPtr[i];
						}
					}
				}
			}
            var increment = ulongOps * sizeof(UInt64);
			aOff += increment;
			bOff += increment;
			length = remainder;
            #endif

            for (var i = 0; i < length; i++) {
                a[aOff + i] ^= b[bOff + i];
            }
        }

        /// <summary>
        ///     Rotate an integer left 
        ///     (<paramref name="i"/> &lt;&lt;&lt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static UInt32 RotateLeft(this UInt32 i, int distance)
        {
            return (i << distance) | (i >> -distance);
        }

        /// <summary>
        ///     Rotate an integer left 
        ///     (<paramref name="i"/> &lt;&lt;&lt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static Int32 RotateLeft(this Int32 i, int distance)
        {
            return (i << distance) ^ (Int32)((UInt32)i >> -distance);
        }

        /// <summary>
        ///     Rotate an integer left 
        ///     (<paramref name="i"/> &lt;&lt;&lt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static UInt64 RotateLeft(this UInt64 i, int distance)
        {
            return (i << distance) | (i >> -distance);
        }

        /// <summary>
        ///     Rotate an integer left 
        ///     (<paramref name="i"/> &lt;&lt;&lt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static Int64 RotateLeft(this Int64 i, int distance)
        {
            return (i << distance) ^ (Int64)((UInt64)i >> -distance);
        }

        /// <summary>
        ///     Rotate an integer right 
        ///     (<paramref name="i"/> &gt;&gt;&gt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static UInt32 RotateRight(this UInt32 i, int distance)
        {
            return (i >> distance) | (i << -distance);
        }

        /// <summary>
        ///     Rotate an integer right 
        ///     (<paramref name="i"/> &gt;&gt;&gt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static Int32 RotateRight(this Int32 i, int distance)
        {
            return (Int32)((UInt32)i >> distance) ^ (i << -distance);
        }

        /// <summary>
        ///     Rotate an integer right 
        ///     (<paramref name="i"/> &gt;&gt;&gt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static UInt64 RotateRight(this UInt64 i, int distance)
        {
            return (i >> distance) | (i << -distance);
        }

        /// <summary>
        ///     Rotate an integer right 
        ///     (<paramref name="i"/> &gt;&gt;&gt; <paramref name="distance"/>).
        /// </summary>
        /// <param name="i">Integer to rotate.</param>
        /// <param name="distance">Distance to rotate.</param>
        /// <returns>Rotated integer.</returns>
        public static Int64 RotateRight(this Int64 i, int distance)
        {
            return (Int64)((UInt64)i >> distance) ^ (i << -distance);
        }

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
            if (data == null) {
                throw new ArgumentNullException("data");
            }
            if (offset < 0) {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (count < 0) {
                throw new ArgumentOutOfRangeException("count", "Count must be positive.");
            }
            if (offset + count > data.Length) {
                throw new ArgumentException("offset + count > data.Length");
            }

            InternalWipe(data, offset, count);
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
                    InternalWipe(ptr, offset, count);
                }
            }
#else
            Array.Clear(data, offset, count);
#endif
        }

#if INCLUDE_UNSAFE
        internal static unsafe void InternalWipe(byte* src, int offset, int length)
        {
            while (length >= 16) {
                *(UInt64*)src = default(UInt64);
                src += 8;
                *(UInt64*)src = default(UInt64);
                src += 8;
                length -= 16;
            }

            if (length >= 8) {
                *(UInt64*)src = default(UInt64);
                src += 8;
                length -= 8;
            }

            if (length >= 4) {
                *(UInt32*)src = default(UInt32);
                src += 4;
                length -= 4;
            }

            if (length >= 2) {
                *(UInt16*)src = default(UInt16);
                src += 2;
                length -= 2;
            }

            if (length != 0) {
                *src = 0x00;
            }
        }
#endif
    }
}
