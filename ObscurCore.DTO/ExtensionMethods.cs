#region License

// 	Copyright 2013-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

#endregion

using System;
using System.Runtime.CompilerServices;

namespace ObscurCore.DTO
{
    internal static class ExtensionMethods
    {
        public static byte[] DeepCopy(this byte[] data)
        {
            if (data == null) {
                return null;
            }
            var dst = new byte[data.Length];
            data.CopyBytes(0, dst, 0, data.Length);
            return dst;
        }

        private const int BufferBlockCopyThreshold = 1024;
#if INCLUDE_UNSAFE
        private const int UnmanagedThreshold = 128;
#endif

        /// <summary>
        ///     Copy bytes from <paramref name="src"/> into <paramref name="dst"/>.
        /// </summary>
        /// <param name="src">The source byte array.</param>
        /// <param name="srcOffset">
        ///     The offset in <paramref name="src"/> at which the source data begins.
        /// </param>
        /// <param name="length">The number of bytes to copy.</param>
        /// <param name="dst">The destination byte array.</param>
        /// <param name="dstOffset">
        ///     The offset in <paramref name="dst"/> at which to copy into.
        /// </param>
        public static void CopyBytes(this byte[] src, int srcOffset, byte[] dst, int dstOffset, int length)
        {
#if INCLUDE_UNSAFE
            if (length >= UnmanagedThreshold) {
                if (srcOffset + length > src.Length || dstOffset + length > dst.Length) {
                    throw new ArgumentException(
                        "Either/both src or dst offset is incompatible with array length. Security risk in unsafe execution!");
                }
                unsafe {
                    fixed (byte* srcPtr = src) {
                        fixed (byte* dstPtr = dst) {
                            CopyMemory(srcPtr + srcOffset, dstPtr + dstOffset, length);
                        }
                    }
                }
            } else {
#endif
                if (length >= BufferBlockCopyThreshold) {
                    Buffer.BlockCopy(src, srcOffset, dst, dstOffset, length);
                } else {
                    Array.Copy(src, srcOffset, dst, dstOffset, length);
                }
#if INCLUDE_UNSAFE
            }
#endif
        }

#if INCLUDE_UNSAFE
        /// <summary>
        ///     Copy data from <paramref name="src"/> into <paramref name="dst"/>.
        /// </summary>
        /// <param name="src">Pointer to source of data.</param>
        /// <param name="dst">Pointer to destination for data.</param>
        /// <param name="length">Length of data to copy in bytes.</param>
        internal static unsafe void CopyMemory(byte* src, byte* dst, int length)
        {
            while (length >= 16) {
                *(ulong*)dst = *(ulong*)src;
                dst += 8;
                src += 8;
                *(ulong*)dst = *(ulong*)src;
                dst += 8;
                src += 8;
                length -= 16;
            }

            if (length >= 8) {
                *(ulong*)dst = *(ulong*)src;
                dst += 8;
                src += 8;
                length -= 8;
            }

            if (length >= 4) {
                *(uint*)dst = *(uint*)src;
                dst += 4;
                src += 4;
                length -= 4;
            }

            if (length >= 2) {
                *(ushort*)dst = *(ushort*)src;
                dst += 2;
                src += 2;
                length -= 2;
            }

            if (length != 0) {
                *dst = *src;
            }
        }
#endif

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
        ///     A constant time equals comparison - does not terminate early if
        ///     test will fail.
        ///     Checks as far as a is in length.
        /// </summary>
        /// <param name="a">Array to compare against</param>
        /// <param name="b">Array to test for equality</param>
        /// <returns>If arrays equal <c>true</c>, false otherwise.</returns>
        public static bool SequenceEqualConstantTime(this byte[] a, byte[] b)
        {
            return a.SequenceEqualConstantTime(0, b, 0, a.Length);
        }

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
            if ((uint)xOffset + (uint)length > (uint)x.Length) {
                throw new ArgumentOutOfRangeException("length", "xOffset + length > x.Length");
            }
            if ((uint)yOffset + (uint)length > (uint)y.Length) {
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
            return (1 & (((uint)differentbits - 1) >> 8));
        }

        public static void SecureWipe(this byte[] data)
        {
            if (data == null) {
                throw new ArgumentNullException("data");
            }

            InternalWipe(data, 0, data.Length);
        }

        public static void SecureWipe(this byte[] data, int offset, int count)
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
                throw new InvalidOperationException();
            }

            InternalWipe(data, offset, count);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void InternalWipe(byte[] data, int offset, int count)
        {
            Array.Clear(data, offset, count);
        }
    }
}
