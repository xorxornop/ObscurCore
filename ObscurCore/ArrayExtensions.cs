using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PerfCopy;

namespace ObscurCore
{
    public static class ArrayExtensions
    {
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
                hc ^= (int)data[i];
            }

            return hc;
        }

        public static byte[] Append(this byte[] a, byte b)
        {
            if (a == null)
                return new byte[] { b };

            int length = a.Length;
            byte[] result = new byte[length + 1];
            a.DeepCopy_NoChecks(0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static short[] Append(this short[] a, short b)
        {
            if (a == null)
                return new short[] { b };

            int length = a.Length;
            short[] result = new short[length + 1];
            a.DeepCopy_NoChecks(0, result, 0, length);
            result[length] = b;
            return result;
        }


        public static T[] Append<T>(this T[] a, T b) where T : struct
        {
            if (a == null)
                return new T[] { b };

            int length = a.Length;

            T[] result = new T[length + 1];
            Array.Copy(a, 0, result, 0, length);
            result[length] = b;

            return result;
        }


        public static int[] Append(this int[] a, int b)
        {
            if (a == null)
                return new int[] { b };

            int length = a.Length;
            int[] result = new int[length + 1];
            a.DeepCopy_NoChecks(0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static byte[] Concatenate(this byte[] a, byte[] b)
        {
            if (a == null)
                return (byte[])b.Clone();
            if (b == null)
                return (byte[])a.Clone();

            byte[] rv = new byte[a.Length + b.Length];
            a.DeepCopy_NoChecks(0, rv, 0, a.Length);
            b.DeepCopy_NoChecks(0, rv, a.Length, b.Length);
            return rv;
        }

        public static int[] Concatenate(this int[] a, int[] b)
        {
            if (a == null)
                return (int[])b.Clone();
            if (b == null)
                return (int[])a.Clone();

            int[] rv = new int[a.Length + b.Length];
            a.DeepCopy_NoChecks(0, rv, 0, a.Length);
            b.DeepCopy_NoChecks(0, rv, a.Length, b.Length);
            return rv;
        }

        public static byte[] Prepend(this byte[] a, byte b)
        {
            if (a == null)
                return new byte[] { b };

            int length = a.Length;
            byte[] result = new byte[length + 1];
            a.DeepCopy_NoChecks(0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static short[] Prepend(this short[] a, short b)
        {
            if (a == null)
                return new short[] { b };

            int length = a.Length;
            short[] result = new short[length + 1];
            a.DeepCopy_NoChecks(0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static int[] Prepend(this int[] a, int b)
        {
            if (a == null)
                return new int[] { b };

            int length = a.Length;
            int[] result = new int[length + 1];
            a.DeepCopy_NoChecks(0, result, 1, length);
            result[0] = b;
            return result;
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

        /// <summary>
        ///     Fill <paramref name="array"/> from <paramref name="offset"/> with 
        ///     <paramref name="length"/> repeats of <paramref name="value"/>.
        /// </summary>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        /// <param name="offset">Offset in <paramref name="array"/> to fill from.</param>
        /// <param name="length">Repeats of <paramref name="value"/> to write.</param>
        public static void Fill(this byte[] array, byte value, int offset, int length)
        {
            Fill_NoChecks(array, value, offset, length);
        }

        /// <summary>
        ///     Fill <paramref name="array"/> from <paramref name="offset"/> with 
        ///     <paramref name="length"/> repeats of <paramref name="value"/>. 
        ///     Caution: Does not perform argument validation.
        /// </summary>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        /// <param name="offset">Offset in <paramref name="array"/> to fill from.</param>
        /// <param name="length">Repeats of <paramref name="value"/> to write.</param>
        public static void Fill_NoChecks(this byte[] array, byte value, int offset, int length)
        {
#if INCLUDE_UNSAFE
            const int umLimit = 128;
            if (length >= umLimit) {
                unsafe {
                    fixed (byte* arrayPtr = &array[offset]) {
                        Fill(arrayPtr, value, length);
                    }
                }
            } else {
#endif
            int endOffset = offset + length;
            for (int i = offset; i < endOffset; i++) {
                array[i] = value;
            }
#if INCLUDE_UNSAFE
            }
#endif
        }

        /// <summary>
        ///     Fill <paramref name="array"/> from <paramref name="offset"/> with 
        ///     <paramref name="length"/> repeats of <paramref name="value"/>.
        /// </summary>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        /// <param name="offset">Offset in <paramref name="array"/> to fill from.</param>
        /// <param name="length">Repeats of <paramref name="value"/> to write.</param>
        public static void Fill(this uint[] array, uint value, int offset, int length)
        {
            Fill_NoChecks(array, value, offset, length);
        }

        /// <summary>
        ///     Fill <paramref name="array"/> from <paramref name="offset"/> with 
        ///     <paramref name="length"/> repeats of <paramref name="value"/>. 
        ///     Caution: Does not perform argument validation.
        /// </summary>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        /// <param name="offset">Offset in <paramref name="array"/> to fill from.</param>
        /// <param name="length">Repeats of <paramref name="value"/> to write.</param>
        public static void Fill_NoChecks(this uint[] array, uint value, int offset, int length)
        {
#if INCLUDE_UNSAFE
            const int umLimit = 128 / sizeof(uint);
            if (length >= umLimit) {
                unsafe {
                    fixed (uint* arrayPtr = &array[offset]) {
                        Fill(arrayPtr, value, length);
                    }
                }
            } else {
#endif
            int endOffset = offset + length;
            for (int i = offset; i < endOffset; i++) {
                array[i] = value;
            }
#if INCLUDE_UNSAFE
            }
#endif
        }

        /// <summary>
        ///     Fill <paramref name="array"/> from <paramref name="offset"/> with 
        ///     <paramref name="length"/> repeats of <paramref name="value"/>.
        /// </summary>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        /// <param name="offset">Offset in <paramref name="array"/> to fill from.</param>
        /// <param name="length">Repeats of <paramref name="value"/> to write.</param>
        public static void Fill(this ulong[] array, ulong value, int offset, int length)
        {
            Fill_NoChecks(array, value, offset, length);
        }

        /// <summary>
        ///     Fill <paramref name="array"/> from <paramref name="offset"/> with 
        ///     <paramref name="length"/> repeats of <paramref name="value"/>. 
        ///     Caution: Does not perform argument validation.
        /// </summary>
        /// <param name="array">Array to fill with <paramref name="value"/>.</param>
        /// <param name="value">Value to fill <paramref name="array"/> with.</param>
        /// <param name="offset">Offset in <paramref name="array"/> to fill from.</param>
        /// <param name="length">Repeats of <paramref name="value"/> to write.</param>
        public static void Fill_NoChecks(this ulong[] array, ulong value, int offset, int length)
        {
#if INCLUDE_UNSAFE
            const int umLimit = 128 / sizeof(ulong);
            if (length >= umLimit) {
                unsafe {
                    fixed (ulong* arrayPtr = &array[offset]) {
                        Fill(arrayPtr, value, length);
                    }
                }
            } else {
#endif
            int endOffset = offset + length;
            for (int i = offset; i < endOffset; i++) {
                array[i] = value;
            }
#if INCLUDE_UNSAFE
            }
#endif
        }

#if INCLUDE_UNSAFE
        private static unsafe void Fill(byte* arrayPtr, byte val, int length)
        {
            byte* endPtr = arrayPtr + length;
            const int u32Size = sizeof(UInt32);
            UInt32 mask32 = val;
            mask32 |= (mask32 << 8)  |
                      (mask32 << 16) |
                      (mask32 << 24);

            if (StratCom.PlatformWordSize == u32Size) {
                while (arrayPtr + (u32Size * 2) <= endPtr) {
                    *(UInt32*)arrayPtr = mask32;
                    arrayPtr += u32Size;
                    *(UInt32*)arrayPtr = mask32;
                    arrayPtr += u32Size;
                }
            } else if (StratCom.PlatformWordSize == sizeof(UInt64)) {
                const int u64Size = sizeof(UInt64);
                UInt64 mask64 = val;
                mask64 |= (mask64 << 8)  |
                          (mask64 << 16) |
                          (mask64 << 24) |
                          (mask64 << 32) |
                          (mask64 << 40) |
                          (mask64 << 48) |
                          (mask64 << 56);
                while (arrayPtr + (u64Size * 2) <= endPtr) {
                    *(UInt64*)arrayPtr = mask64;
                    arrayPtr += u64Size;
                    *(UInt64*)arrayPtr = mask64;
                    arrayPtr += u64Size;
                }
                if (arrayPtr + u64Size <= endPtr) {
                    *(UInt64*)arrayPtr = mask64;
                    arrayPtr += u64Size;
                }
            }
            if (arrayPtr + u32Size <= endPtr) {
                *(UInt32*)arrayPtr = mask32;
                arrayPtr += u32Size;
            }
            if (arrayPtr + sizeof(UInt16) <= endPtr) {
                *(UInt16*)arrayPtr = (UInt16)mask32;
                arrayPtr += sizeof(UInt16);
            }
            if (arrayPtr <= endPtr) {
                *arrayPtr = val;
            }
        }

        private static unsafe void Fill(uint* arrayPtr, uint val, int length)
        {
            uint* endPtr = arrayPtr + length;
            UInt32 mask32 = val;

            if (StratCom.PlatformWordSize == sizeof(UInt32)) {
                while (arrayPtr + 2 <= endPtr) {
                    *arrayPtr = mask32;
                    arrayPtr++;
                    *arrayPtr = mask32;
                    arrayPtr++;
                }
            } else if (StratCom.PlatformWordSize == sizeof(UInt64)) {
                UInt64 mask64 = val;
                mask64 |= mask64 << 32;
                while (arrayPtr + 4 <= endPtr) {
                    *(UInt64*)arrayPtr = mask64;
                    arrayPtr += 2;
                    *(UInt64*)arrayPtr = mask64;
                    arrayPtr += 2;
                }
            }
            if (arrayPtr + 1 <= endPtr) {
                *arrayPtr = mask32;
            }
        }

        private static unsafe void Fill(ulong* arrayPtr, ulong val, int length)
        {
            ulong* endPtr = arrayPtr + length;
            for (; arrayPtr < endPtr + 1; arrayPtr++) {
                *arrayPtr = val;
            }
        }
#endif
    }
}
