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

namespace ObscurCore.Cryptography
{
	public static class CryptographyExtensions
	{
		/// <summary>
		/// A constant time equals comparison - does not terminate early if
		/// test will fail.
		/// </summary>
		/// <param name="a">Array to compare against</param>
		/// <param name="b">Array to test for equality</param>
		/// <returns>If arrays equal <c>true</c>, false otherwise.</returns>
		public static bool SequenceEqualConstantTime (this byte[] a, byte[] b) {
			if (a.Length != b.Length)
				return false;

			int cmp = 0;
			for (int i = a.Length - 1; i >= 0; i--) {
				cmp |= (a [i] ^ b [i]);
			}
			return cmp == 0;
		}

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
		public static void XOR(this byte[] a, int aOff, byte[] b, int bOff, byte[] c, int cOff, int length) {
			#if INCLUDE_UNSAFE
			int remainder;
			int uintOps = Math.DivRem(length, sizeof(uint), out remainder);
			unsafe {
				fixed (byte* aPtr = a) {
					fixed (byte* bPtr = b) {
						fixed (byte* cPtr = c) {
							uint* aUintPtr = (uint*)(aPtr + aOff);
							uint* bUintPtr = (uint*)(bPtr + bOff);
							uint* cUintPtr = (uint*)(cPtr + cOff);
							for (int i = 0; i < uintOps; i++) {
								cUintPtr[i] = aUintPtr[i] ^ bUintPtr[i];
							}
						}
					}
				}
			}
			int increment = uintOps * sizeof(uint);
			aOff += increment;
			bOff += increment;
			cOff += increment;
			for (int i = 0; i < remainder; i++) {
				c[cOff + i] = (byte) (a[aOff + i] ^ b[bOff + i]);
			}
			#else
			for (int i = 0; i < length; i++) {
				c[cOff + i] = (byte)(a[aOff + i] ^ b[bOff + i]);
			}
			#endif
		}

		public static void XORInPlace(this byte[] a, int aOff, byte[] b, int bOff, int length) {
			if (length <= 0) {
				throw new ArgumentException ("Length is not positive.", "length");
			} else if (aOff + length > a.Length) {
				throw new ArgumentException ("Insufficient length.", "a");
			} else if (bOff + length > b.Length) {
				throw new ArgumentException ("Insufficient length.", "b");
			}

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
			for (int i = 0; i < remainder; i++) {
				a[aOff + i] ^= b[bOff + i];
			}
			#else
			for (int i = 0; i < length; i++) {
				a[aOff + i] ^= b[bOff + i];
			}
			#endif
		}


	}
}

