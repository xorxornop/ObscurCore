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

namespace ObscurCore.Cryptography.Entropy
{
    /// <summary>
    ///     Base class to derive pseudorandom number generators (PRNGs) from.
    /// </summary>
    public abstract class Csprng : Random
    {
        private readonly byte[] _dblBuf = new byte[8];
        private readonly byte[] _intBuf = new byte[4];

        protected internal static int Log2(int number)
        {
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
        ///     Generate an integer between 0 (inclusive) and maxValue (exclusive).
        /// </summary>
        /// <param name="maxValue">Maximum value of output, exclusive.</param>
        public override int Next(int maxValue)
        {
            if (maxValue < 2) {
                if (maxValue < 0) {
                    throw new ArgumentOutOfRangeException("maxValue", "maxValue < 0");
                }

                return 0;
            }

            // Test whether maxValue is a power of 2
            if ((maxValue & -maxValue) == maxValue) {
                int val = Next() & Int32.MaxValue;
                long lr = (maxValue * (long) val) >> 31;
                return (int) lr;
            }

            int bits, result;
            do {
                bits = Next() & Int32.MaxValue;
                result = bits % maxValue;
            } while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

            return result;
        }

        /// <summary>
        ///     Generate an integer between minValue (inclusive) and maxValue (exclusive).
        /// </summary>
        /// <param name="minValue">Minimum value of output, inclusive.</param>
        /// <param name="maxValue">Maximum value of output, exclusive.</param>
        public override int Next(int minValue, int maxValue)
        {
            if (maxValue <= minValue) {
                if (maxValue == minValue) {
                    return minValue;
                }

                throw new ArgumentException("maxValue cannot be less than minValue");
            }

            int diff = maxValue - minValue;
            if (diff > 0) {
                return minValue + Next(diff);
            }

            int i;
            do {
                i = Next();
            } while (i < minValue && i > maxValue);

            return i;
        }

        /// <summary>
        ///     Generate an integer between zero and the maximum positive range of an Int32.
        /// </summary>
        public override int Next()
        {
            NextBytes(_intBuf);
            int num = _intBuf.LittleEndianToInt32() & Int32.MaxValue;
            return num;
        }

        /// <summary>
        ///     Generate a 32-bit unsigned integer.
        /// </summary>
        public UInt32 NextUInt32()
        {
            NextBytes(_intBuf);
            return _intBuf.LittleEndianToUInt32();
        }

        public override double NextDouble()
        {
            return Sample();
        }

        protected override double Sample()
        {
            NextBytes(_dblBuf);
            ulong ul = _dblBuf.LittleEndianToUInt64() >> 11;
            return ul / (double) (1UL << 53);
        }

        public abstract override void NextBytes(byte[] buffer);
    }
}
