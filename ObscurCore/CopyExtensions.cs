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
    /// Extension methods for copying data.
    /// </summary>
    public static class CopyExtensions
    {
        private const int DeepCopyBufferBlockCopyThreshold = 16384;
#if INCLUDE_UNSAFE
        private const int DeepCopyUnmanagedThreshold = 64;
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
            if (length >= DeepCopyUnmanagedThreshold) {
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
            } else {
#endif
                if (length >= DeepCopyBufferBlockCopyThreshold) {
                    Buffer.BlockCopy(src, srcOffset, dst, dstOffset, length);
                } else {
                    Array.Copy(src, srcOffset, dst, dstOffset, length);
                }
#if INCLUDE_UNSAFE
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
            const int umLimit = DeepCopyUnmanagedThreshold / sizeof(int);
            if (src.Length >= umLimit) {
                unsafe {
                    fixed (int* srcPtr = src) {
                        fixed (int* dstPtr = dst) {
                            var srcBP = (byte*)srcPtr;
                            var dstBP = (byte*)dstPtr;
                            CopyMemory(dstBP, srcBP, src.Length * sizeof(int));
                        }
                    }
                }
            } else {
#endif
                const int bcLimit = DeepCopyBufferBlockCopyThreshold / sizeof(int);
                if (src.Length >= bcLimit)
                    Buffer.BlockCopy(src, 0, dst, 0, src.Length);
                else
                    Array.Copy(src, 0, dst, 0, src.Length);
#if INCLUDE_UNSAFE
            }
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
            const int umLimit = DeepCopyUnmanagedThreshold / sizeof(long);
            if (src.Length >= umLimit) {
                unsafe {
                    fixed (long* srcPtr = src) {
                        fixed (long* dstPtr = dst) {
                            var srcBP = (byte*)srcPtr;
                            var dstBP = (byte*)dstPtr;
                            CopyMemory(dstBP, srcBP, src.Length * sizeof(long));
                        }
                    }
                }
            } else {
#endif
                const int bcLimit = DeepCopyBufferBlockCopyThreshold / sizeof(long);
                if (src.Length >= bcLimit)
                    Buffer.BlockCopy(src, 0, dst, 0, src.Length);
                else
                    Array.Copy(src, 0, dst, 0, src.Length);
#if INCLUDE_UNSAFE
            }
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
            const int umLimit = DeepCopyUnmanagedThreshold / sizeof(ulong);
            if (src.Length >= umLimit) {
                unsafe {
                    fixed (ulong* srcPtr = src) {
                        fixed (ulong* dstPtr = dst) {
                            var srcBP = (byte*)srcPtr;
                            var dstBP = (byte*)dstPtr;
                            CopyMemory(dstBP, srcBP, src.Length * sizeof(ulong));
                        }
                    }
                }
            } else {
#endif
                const int bcLimit = DeepCopyBufferBlockCopyThreshold / sizeof(ulong);
                if (src.Length >= bcLimit)
                    Buffer.BlockCopy(src, 0, dst, 0, src.Length);
                else
                    Array.Copy(src, 0, dst, 0, src.Length);
#if INCLUDE_UNSAFE
            }
#endif
        }

#if INCLUDE_UNSAFE
        internal static unsafe void CopyMemory(byte* dst, byte* src, int length)
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
    }
}
