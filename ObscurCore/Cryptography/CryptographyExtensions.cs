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
	public static class CryptographyExtensions
	{
		/// <summary>
		/// A constant time equals comparison - does not terminate early if
		/// test will fail. 
		/// Checks as far as a is in length.
		/// </summary>
		/// <param name="a">Array to compare against</param>
		/// <param name="b">Array to test for equality</param>
		/// <returns>If arrays equal <c>true</c>, false otherwise.</returns>
		public static bool SequenceEqualConstantTime (this byte[] a, byte[] b) {
			return a.SequenceEqualConstantTime(0, b, 0, a.Length);
		}

		public static bool SequenceEqualConstantTime(this byte[] x, int xOffset, byte[] y, int yOffset, int length)
		{
			if (x == null)
				throw new ArgumentNullException("x");
			if (xOffset < 0)
				throw new ArgumentOutOfRangeException("xOffset", "xOffset < 0");
			if (y == null)
				throw new ArgumentNullException("y");
			if (yOffset < 0)
				throw new ArgumentOutOfRangeException("yOffset", "yOffset < 0");
			if (length < 0)
				throw new ArgumentOutOfRangeException("length", "length < 0");
			if ((uint)xOffset + (uint)length > (uint)x.Length)
				throw new ArgumentOutOfRangeException("length", "xOffset + length > x.Length");
			if ((uint)yOffset + (uint)length > (uint)y.Length)
				throw new ArgumentOutOfRangeException("length", "yOffset + length > y.Length");

			return InternalConstantTimeEquals(x, xOffset, y, yOffset, length) != 0;
		}

		// From CodesInChaos
		private static uint InternalConstantTimeEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length) {
			int differentbits = 0;
			for (int i = 0; i < length; i++)
				differentbits |= x[xOffset + i] ^ y[yOffset + i];
			return (1 & (((uint)differentbits - 1) >> 8));
		}

		/*
		 * Original implementation of constant-time equals (BC):
		 * 
		 * if (a.Length != b.Length)
				return false;

			int cmp = 0;
			for (int i = a.Length - 1; i >= 0; i--) {
				cmp |= (a [i] ^ b [i]);
			}
			return cmp == 0;
		*/


		/// <summary>
		/// XOR the specified a & b arrays into c.
		/// </summary>
		/// <param name="a">Source #0 array.</param>
		/// <param name="aOff">Source array #0 offset.</param>
		/// <param name="b">Source #1 array.</param>
		/// <param name="bOff">Source #1 array offset.</param>
		/// <param name="c">Destination array.</param>
		/// <param name="cOff">Destination array offset.</param>
		/// <param name="length">Length to XOR.</param>
		public static void XOR(this byte[] a, int aOff, byte[] b, int bOff, byte[] output, int outputOff, int length) {
			if (length <= 0) {
				throw new ArgumentException ("Length is not positive.", "length");
			} else if (aOff < 0) {
				throw new ArgumentOutOfRangeException("aOff", "aOff must be 0 or positive.");
			} else if (aOff + length > a.Length) {
				throw new ArgumentException ("Insufficient length.", "a");
			} else if (bOff < 0) {
				throw new ArgumentOutOfRangeException("bOff", "bOff must be 0 or positive.");
			} else if (bOff + length > b.Length) {
				throw new ArgumentException ("Insufficient length.", "b");
			} else if (outputOff < 0) {
				throw new ArgumentOutOfRangeException("cOff", "cOff must be 0 or positive.");
			}  else if (outputOff + length > output.Length) {
				throw new DataLengthException ("Insufficient length.", "c");
			}

			XORNoChecks (a, aOff, b, bOff, output, outputOff, length);
		}

		internal static void XORNoChecks(this byte[] a, int aOff, byte[] b, int bOff, byte[] output, int outputOff, int length) {
			#if INCLUDE_UNSAFE
			int remainder;
			int uintOps = Math.DivRem(length, sizeof(uint), out remainder);
			unsafe {
				fixed (byte* aPtr = a) {
					fixed (byte* bPtr = b) {
						fixed (byte* outputPtr = output) {
							uint* aUintPtr = (uint*)(aPtr + aOff);
							uint* bUintPtr = (uint*)(bPtr + bOff);
							uint* outputUintPtr = (uint*)(outputPtr + outputOff);
							for (int i = 0; i < uintOps; i++) {
								outputUintPtr[i] = aUintPtr[i] ^ bUintPtr[i];
							}
						}
					}
				}
			}
			int increment = uintOps * sizeof(uint);
			aOff += increment;
			bOff += increment;
			outputOff += increment;
			length = remainder;
			#endif

			for (int i = 0; i < length; i++) {
				output[outputOff + i] = (byte)(a[aOff + i] ^ b[bOff + i]);
			}
		}

		/// <summary>
		/// XOR the specified array 'b' into 'a' in-place.
		/// </summary>
		/// <param name="a">Destination and source #0 array.</param>
		/// <param name="aOff">Destination and source array #0 offset.</param>
		/// <param name="b">Source #1 array.</param>
		/// <param name="bOff">Source #1 array offset.</param>
		/// <param name="length">Length to XOR.</param>
		public static void XORInPlace(this byte[] a, int aOff, byte[] b, int bOff, int length) {
			if (length <= 0) {
				throw new ArgumentException ("Length is not positive.", "length");
			} else if (aOff < 0) {
				throw new ArgumentOutOfRangeException("aOff", "aOff must be 0 or positive.");
			} else if (aOff + length > a.Length) {
				throw new ArgumentException ("Insufficient length.", "a");
			} else if (bOff < 0) {
				throw new ArgumentOutOfRangeException("bOff", "bOff must be 0 or positive.");
			} else if (bOff + length > b.Length) {
				throw new ArgumentException ("Insufficient length.", "b");
			}

			XORInPlaceNoChecks (a, aOff, b, bOff, length);
		}

		internal static void XORInPlaceNoChecks(this byte[] a, int aOff, byte[] b, int bOff, int length) {
			#if INCLUDE_UNSAFE
			int remainder;
			int uintOps = Math.DivRem(length, sizeof(uint), out remainder);
			unsafe {
				fixed (byte* aPtr = a) {
					fixed (byte* bPtr = b) {
						uint* aUintPtr = (uint*)(aPtr + aOff);
						uint* bUintPtr = (uint*)(bPtr + bOff);
						for (int i = 0; i < uintOps; i++) {
							aUintPtr[i] ^= bUintPtr[i];
						}

					}
				}
			}
			int increment = uintOps * sizeof(uint);
			aOff += increment;
			bOff += increment;
			length = remainder;
			#endif

			for (int i = 0; i < length; i++) {
				a[aOff + i] ^= b[bOff + i];
			}
		}

		public static int RotateLeft(this int i, int distance) {
			return (i << distance) ^ (int)((uint)i >> -distance);
		}

		public static int RotateRight(this int i, int distance) {
			return (int)((uint)i >> distance) ^ (i << -distance);
		}

		public static void SecureWipe(this byte[] data) {
			if (data == null)
				throw new ArgumentNullException("data");

			InternalWipe(data, 0, data.Length);
		}

		public static void SecureWipe(this byte[] data, int offset, int count) {
			if (data == null)
				throw new ArgumentNullException("data");
			if (offset < 0)
				throw new ArgumentOutOfRangeException("offset");
			if (count < 0)
				throw new ArgumentOutOfRangeException("count", "Count must be positive.");
			if (offset + count > data.Length)
				throw new DataLengthException ();

			InternalWipe(data, offset, count);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		public static void InternalWipe(byte[] data, int offset, int count) {
			Array.Clear(data, offset, count);
		}

		/* BIT PACKING METHODS */

		// Big endian
		// Int32

		public static byte[] ToBigEndian(this Int32 n) {
			byte[] bs = new byte[sizeof (Int32)];
			n.ToBigEndian(bs);
			return bs;
		}

		public static void ToBigEndian(this Int32 n, byte[] bs) {
			bs[0] = (byte) (n >> 24);
			bs[1] = (byte) (n >> 16);
			bs[2] = (byte) (n >> 8);
			bs[3] = (byte) (n);
		}

		public static void ToBigEndian(this Int32 n, byte[] bs, int off) {
			bs[off + 0] = (byte) (n >> 24);
			bs[off + 1] = (byte) (n >> 16);
			bs[off + 2] = (byte) (n >> 8);
			bs[off + 3] = (byte) (n);
		}

		public static Int32 BigEndianToInt32(this byte[] bs) {
			return (Int32) bs[0] << 24 
				| (Int32) bs[1] << 16 
				| (Int32) bs[2] << 8 
				| (Int32) bs[3];
		}

		public static Int32 BigEndianToInt32(this byte[] bs, int off) {
			return (Int32) bs[off] << 24 
				| (Int32) bs[off + 1] << 16 
				| (Int32) bs[off + 2] << 8 
				| (Int32) bs[off + 3];
		}

		// UInt32

		[CLSCompliantAttribute(false)]
		public static byte[] ToBigEndian(this UInt32 n) {
			byte[] bs = new byte[sizeof (UInt32)];
			n.ToBigEndian(bs);
			return bs;
		}

		[CLSCompliantAttribute(false)]
		public static void ToBigEndian(this UInt32 n, byte[] bs) {
			bs[0] = (byte) (n >> 24);
			bs[1] = (byte) (n >> 16);
			bs[2] = (byte) (n >> 8);
			bs[3] = (byte) (n);
		}

		[CLSCompliantAttribute(false)]
		public static void ToBigEndian(this UInt32 n, byte[] bs, int off) {
			bs[off + 0] = (byte) (n >> 24);
			bs[off + 1] = (byte) (n >> 16);
			bs[off + 2] = (byte) (n >> 8);
			bs[off + 3] = (byte) (n);
		}

		[CLSCompliantAttribute(false)]
		public static UInt32 BigEndianToUInt32(this byte[] bs) {
			return (UInt32) bs[0] << 24 
				| (UInt32) bs[1] << 16 
				| (UInt32) bs[2] << 8 
				| (UInt32) bs[3];
		}

		[CLSCompliantAttribute(false)]
		public static UInt32 BigEndianToUInt32(this byte[] bs, int off) {
			return (UInt32) bs[off] << 24 
				| (UInt32) bs[off + 1] << 16 
				| (UInt32) bs[off + 2] << 8 
				| (UInt32) bs[off + 3];
		}

		// UInt64

		[CLSCompliantAttribute(false)]
		public static byte[] ToBigEndian(this UInt64 n) {
			var bs = new byte[sizeof (UInt64)];
			n.ToBigEndian(bs);
			return bs;
		}

		[CLSCompliantAttribute(false)]
		public static void ToBigEndian(this UInt64 n, byte[] bs) {
			((UInt32) (n >> 32)).ToBigEndian(bs, 0);
			((UInt32) (n)).ToBigEndian(bs, 4);
		}

		[CLSCompliantAttribute(false)]
		public static void ToBigEndian(this UInt64 n, byte[] bs, int off) {
			((UInt32) (n >> 32)).ToBigEndian(bs, off);
			((UInt32) (n)).ToBigEndian(bs, off + 4);
		}

		[CLSCompliantAttribute(false)]
		public static UInt64 BigEndianToUInt64(this byte[] bs) {
			UInt32 hi = bs.BigEndianToUInt32();
			UInt32 lo = bs.BigEndianToUInt32(4);
			return ((UInt64) hi << 32) | (UInt64) lo;
		}

		[CLSCompliantAttribute(false)]
		public static UInt64 BigEndianToUInt64(this byte[] bs, int off) {
			UInt32 hi = bs.BigEndianToUInt32(off);
			UInt32 lo = bs.BigEndianToUInt32(off + 4);
			return ((UInt64) hi << 32) | (UInt64) lo;
		}

		// Little endian
		// Int32

		public static byte[] ToLittleEndian(this Int32 n) {
			byte[] bs = new byte[sizeof (Int32)];
			n.ToLittleEndian(bs);
			return bs;
		}

		public static void ToLittleEndian(this Int32 n, byte[] bs) {
			bs[0] = (byte) (n);
			bs[1] = (byte) (n >> 8);
			bs[2] = (byte) (n >> 16);
			bs[3] = (byte) (n >> 24);
		}

		public static void ToLittleEndian(this Int32 n, byte[] bs, int off) {
			bs[off + 0] = (byte) (n);
			bs[off + 1] = (byte) (n >> 8);
			bs[off + 2] = (byte) (n >> 16);
			bs[off + 3] = (byte) (n >> 24);
		}

		public static Int32 LittleEndianToInt32(this byte[] bs) {
			return (Int32) bs[0] 
				| (Int32) bs[1] << 8 
				| (Int32) bs[2] << 16 
				| (Int32) bs[3] << 24;
		}

		public static Int32 LittleEndianToInt32(this byte[] bs, int off) {
			return (Int32) bs[off] 
				| (Int32) bs[off + 1] << 8 
				| (Int32) bs[off + 2] << 16 
				| (Int32) bs[off + 3] << 24;
		}

		// UInt32

		[CLSCompliantAttribute(false)]
		public static byte[] ToLittleEndian(this UInt32 n) {
			byte[] bs = new byte[sizeof (UInt32)];
			n.ToLittleEndian(bs);
			return bs;
		}

		[CLSCompliantAttribute(false)]
		public static void ToLittleEndian(this UInt32 n, byte[] bs) {
			bs[0] = (byte) (n);
			bs[1] = (byte) (n >> 8);
			bs[2] = (byte) (n >> 16);
			bs[3] = (byte) (n >> 24);
		}

		[CLSCompliantAttribute(false)]
		public static void ToLittleEndian(this UInt32 n, byte[] bs, int off) {
			bs[off + 0] = (byte) (n);
			bs[off + 1] = (byte) (n >> 8);
			bs[off + 2] = (byte) (n >> 16);
			bs[off + 3] = (byte) (n >> 24);
		}

		[CLSCompliantAttribute(false)]
		public static UInt32 LittleEndianToUInt32(this byte[] bs) {
			return (UInt32) bs[0] 
				| (UInt32) bs[1] << 8 
				| (UInt32) bs[2] << 16 
				| (UInt32) bs[3] << 24;
		}

		[CLSCompliantAttribute(false)]
		public static UInt32 LittleEndianToUInt32(this byte[] bs, int off) {
			return (UInt32) bs[off] 
				| (UInt32) bs[off + 1] << 8 
				| (UInt32) bs[off + 2] << 16 
				| (UInt32) bs[off + 3] << 24;
		}

		// UInt64

		[CLSCompliantAttribute(false)]
		public static byte[] ToLittleEndian(this UInt64 n) {
			byte[] bs = new byte[sizeof (UInt64)];
			n.ToLittleEndian(bs);
			return bs;
		}

		[CLSCompliantAttribute(false)]
		public static void ToLittleEndian(this UInt64 n, byte[] bs) {
			((UInt32) n).ToLittleEndian(bs, 0);
			((UInt32) (n >> 32)).ToLittleEndian(bs, 4);
		}

		[CLSCompliantAttribute(false)]
		public static void ToLittleEndian(this UInt64 n, byte[] bs, int off) {
			((UInt32) n).ToLittleEndian(bs, off);
			((UInt32) (n >> 32)).ToLittleEndian(bs, off + 4);
		}

		[CLSCompliantAttribute(false)]
		public static UInt64 LittleEndianToUInt64(this byte[] bs) {
			UInt32 lo = bs.LittleEndianToUInt32(0);
			UInt32 hi = bs.LittleEndianToUInt32(4);
			return ((UInt64) hi << 32) | (UInt64) lo;
		}

		[CLSCompliantAttribute(false)]
		public static UInt64 LittleEndianToUInt64(this byte[] bs, int off) {
			UInt32 lo = bs.LittleEndianToUInt32(off);
			UInt32 hi = bs.LittleEndianToUInt32(off + 4);
			return ((UInt64) hi << 32) | (UInt64) lo;
		}


	}
}

