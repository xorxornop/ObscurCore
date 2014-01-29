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

namespace ObscurCore.Cryptography.Entropy
{
	/// <summary>
	/// Base class to derive pseudorandom number generators (PRNGs) from.
	/// </summary>
	public abstract class Csprng : Random
	{
        private readonly byte[] intBuf = new byte[4], dblBuf = new byte[8];

		protected internal static int Log2 (int number) {
			int bits = 0;
			if (number > 32767) {
				number >>= 16;
				bits += 16;
			}
			if (number > 127) {
				number >>= 8;
				bits += 8;
			}
			if (number > 7) {
				number >>= 4;
				bits += 4;
			}
			if (number > 1) {
				number >>= 2;
				bits += 2;
			}
			if (number > 0) {
				bits++;
			}
			return bits;
		}

		/// <summary>
		/// Takes 4 bytes from the CSPRNG and truncates the output to a specified number of bits. 
		/// Truncated data is discarded. 
		/// Caution: No input validation is performed.
		/// </summary>
		/// <returns>Truncated generated integer.</returns>
		/// <param name="bitsToCollect">Bits to collect out of a possible 32.</param>
		protected internal int NextBits (int bitsToCollect) {
			uint mask = 0x00000001u << (bitsToCollect - 1);
			uint num = NextUInt32 ();
			return (int)(num & mask);
		}

		/// <summary>
		/// Generate an integer between 0 and maxValue, inclusive.
		/// </summary>
		/// <param name="maxValue">Maximum value of output, inclusive.</param>
		public override int Next (int maxValue) {
			if (++maxValue <= 0) // maxValue now denotes an EXCLUSIVE maximum, rather than inclusive
				throw new ArgumentException("n must be positive");

			if ((maxValue & -maxValue) == maxValue)  // i.e., n is a power of 2
				return (int)((maxValue * (long)NextBits(31)) >> 31);

			int bits, val;
			do {
				bits = NextBits(31);
				val = bits % maxValue;
			} while (bits - val + (maxValue - 1) < 0);

			return val;
		}

		/// <summary>
		/// Generate an integer between minValue and maxValue, inclusive.
		/// </summary>
		/// <param name="minValue">Minimum value of output, inclusive.</param>
		/// <param name="maxValue">Maximum value of output, inclusive.</param>
		public override int Next(int minValue, int maxValue) {
			int range = maxValue - minValue;
			int num = minValue + Next (range);
			return num;
        }

		/// <summary>
		/// Generate an integer.
		/// </summary>
		public override int Next() {
			NextBytes(intBuf);
			int num = intBuf.LittleEndianToInt32 ();
			return num;
		}

		/// <summary>
		/// Generate an unsigned integer.
		/// </summary>
		public UInt32 NextUInt32() {
			NextBytes(intBuf);
			return intBuf.LittleEndianToUInt32 ();
		}

		public override double NextDouble () { return Sample(); }
		
		protected override double Sample () {
			NextBytes(dblBuf);
			var ul = BitConverter.ToUInt64(dblBuf, 0) >> 11; // cleaner version
			return ul / (double) (1UL << 53);
		}

	    public abstract override void NextBytes(byte[] buffer);
	}
}
