using System;
using System.Runtime.CompilerServices;

namespace ObscurCore.Cryptography.Support
{
	internal sealed class Pack
	{
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt16_To_BE(ushort n, byte[] bs)
		{
		    n.ToBigEndian(bs);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt16_To_BE(ushort n, byte[] bs, int off)
		{
            n.ToBigEndian(bs, off);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ushort BE_To_UInt16(byte[] bs)
		{
		    return bs.BigEndianToUInt16();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ushort BE_To_UInt16(byte[] bs, int off)
		{
            return bs.BigEndianToUInt16(off);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static byte[] UInt32_To_BE(uint n)
		{
            return n.ToBigEndian();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt32_To_BE(uint n, byte[] bs)
		{
            n.ToBigEndian(bs);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt32_To_BE(uint n, byte[] bs, int off)
		{
            n.ToBigEndian(bs, off);
		}

		internal static byte[] UInt32_To_BE(uint[] ns)
		{
			byte[] bs = new byte[sizeof(UInt32) * ns.Length];
			UInt32_To_BE(ns, bs, 0);
			return bs;
		}


		internal static void UInt32_To_BE(uint[] ns, byte[] bs, int off)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				UInt32_To_BE(ns[i], bs, off);
				off += 4;
			}
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static uint BE_To_UInt32(byte[] bs)
		{
		    return bs.BigEndianToUInt32();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static uint BE_To_UInt32(byte[] bs, int off)
		{
            return bs.BigEndianToUInt32(off);
		}

		internal static void BE_To_UInt32(byte[] bs, int off, uint[] ns)
		{
			for (int i = 0; i < ns.Length; ++i)
			{
				ns[i] = BE_To_UInt32(bs, off);
                off += sizeof(UInt32);
			}
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static byte[] UInt64_To_BE(ulong n)
		{
		    return n.ToBigEndian();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt64_To_BE(ulong n, byte[] bs)
		{
            n.ToBigEndian(bs);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt64_To_BE(ulong n, byte[] bs, int off)
		{
		    n.ToBigEndian(bs, off);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ulong BE_To_UInt64(byte[] bs)
		{
		    return bs.BigEndianToUInt64();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ulong BE_To_UInt64(byte[] bs, int off)
		{
            return bs.BigEndianToUInt64(off);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt16_To_LE(ushort n, byte[] bs)
		{
		    n.ToLittleEndian(bs);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt16_To_LE(ushort n, byte[] bs, int off)
		{
            n.ToLittleEndian(bs, off);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ushort LE_To_UInt16(byte[] bs)
		{
            return bs.BigEndianToUInt16();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ushort LE_To_UInt16(byte[] bs, int off)
		{
            return bs.BigEndianToUInt16(off);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static byte[] UInt32_To_LE(uint n)
		{
		    return n.ToLittleEndian();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt32_To_LE(uint n, byte[] bs)
		{
		    n.ToLittleEndian(bs);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt32_To_LE(uint n, byte[] bs, int off)
		{
            n.ToLittleEndian(bs, off);
		}

		internal static byte[] UInt32_To_LE(uint[] ns)
		{
            byte[] bs = new byte[sizeof(UInt32) * ns.Length];
			UInt32_To_LE(ns, bs, 0);
			return bs;
		}

		internal static void UInt32_To_LE(uint[] ns, byte[] bs, int off)
		{
		    int len = ns.Length;
            #if INCLUDE_UNSAFE
            unsafe {
                fixed (uint* inPtr = ns) {
                    fixed (byte* outPtr = bs) {
                        var outUintPtr = (uint*)(outPtr + off);
                        for (var i = 0; i < len; i++) {
                            outUintPtr[i] = inPtr[i];
                        }
                    }
                }
            }
            #else
            for (int i = 0; i < len; ++i)
			{
				UInt32_To_LE(ns[i], bs, off);
				off += 4;
			}
            #endif
		}

        internal static void UInt32_To_LE(uint[] input, int inOff, byte[] output, int outOff)
        {
            var len = input.Length - inOff;
#if INCLUDE_UNSAFE
            unsafe {
                fixed (uint* inPtr = input) {
                    var inUintPtr = (inPtr + inOff);
                    fixed (byte* outPtr = output) {
                        var outUintPtr = (uint*)(outPtr + outOff);
                        for (var i = 0; i < len; i++) {
                            outUintPtr[i] = inUintPtr[i];
                        }
                    }
                }
            }
#else
            for (int i = 0; i < len; ++i)
			{
				UInt32_To_LE(input[i + inOff], output, i + outOff);
			}
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static uint LE_To_UInt32(byte[] bs)
		{
		    return bs.LittleEndianToUInt32();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static uint LE_To_UInt32(byte[] bs, int off)
		{
            return bs.LittleEndianToUInt32(off);
		}

		internal static void LE_To_UInt32(byte[] bs, int off, uint[] ns)
		{
#if INCLUDE_UNSAFE
            unsafe {
                fixed (byte* inPtr = bs) {
                    var inUintPtr = (uint*)inPtr + off;
                    fixed (uint* outPtr = ns) {
                        var nsLen = ns.Length;
                        for (var i = 0; i < nsLen; i++) {
                            outPtr[i] = inUintPtr[i];
                        }
                    }
                }
            }
#else
			for (int i = 0; i < ns.Length; ++i)
			{
				ns[i] = LE_To_UInt32(bs, off);
				off += 4;
			}
#endif
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static byte[] UInt64_To_LE(ulong n)
		{
		    return n.ToLittleEndian();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt64_To_LE(ulong n, byte[] bs)
		{
            n.ToLittleEndian(bs);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void UInt64_To_LE(ulong n, byte[] bs, int off)
		{
            n.ToLittleEndian(bs, off);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ulong LE_To_UInt64(byte[] bs)
		{
		    return bs.LittleEndianToUInt64();
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static ulong LE_To_UInt64(byte[] bs, int off)
		{
            return bs.LittleEndianToUInt64(off);
		}
	}
}
