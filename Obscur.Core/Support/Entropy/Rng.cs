#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using BitManipulator;
using Obscur.Core.Packaging.Multiplexing;

namespace Obscur.Core.Support.Entropy
{
    /// <summary>
    ///     Base class for random number generators (RNGs).
    /// </summary>
    public abstract class Rng : Random
    {
        /// <summary>
        ///     Generate an integer between zero and the maximum positive range of an Int32.
        /// </summary>
        public override sealed int Next()
        {
            int num = NextBytes(sizeof(Int32)).LittleEndianToInt32() & Int32.MaxValue;
            return num;
        }

        /// <summary>
        ///     Generate a 32-bit unsigned integer.
        /// </summary>
        public UInt32 NextUInt32()
        {
            return NextBytes(sizeof(UInt32)).LittleEndianToUInt32();
        }

        /// <summary>
        ///     Generate a 64-bit unsigned integer.
        /// </summary>
        public UInt64 NextUInt64()
        {
            return NextBytes(sizeof(UInt64)).LittleEndianToUInt64();
        }

        /// <summary>
        ///     Generate an integer between 0 (inclusive) and maxValue (exclusive).
        /// </summary>
        /// <remarks>
        ///     Consistency of results from this generator in derived methods must
        ///     be maintained after code modification through versions.
        ///     Output of this method is used for, among other things,
        ///     stream and stride length selection in <see cref="PayloadMux" />.
        /// </remarks>
        /// <param name="maxValue">Maximum value of output, exclusive.</param>
        public override sealed int Next(int maxValue)
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
        public override sealed int Next(int minValue, int maxValue)
        {
            if (maxValue <= minValue) {
                if (maxValue != minValue) {
                    throw new ArgumentException("maxValue cannot be less than minValue");
                }
                return minValue;
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

        /// <inheritdoc />
        public override sealed double NextDouble()
        {
            return Sample();
        }

        /// <inheritdoc />
        protected override double Sample()
        {
            byte[] buf = NextBytes(sizeof(double));
            ulong ul = buf.LittleEndianToUInt64() >> 11;
            return ul / (double) (1UL << 53);
        }

        /// <summary>
        ///     Generate and return a number of random bytes.
        /// </summary>
        /// <param name="count">Number of bytes to return.</param>
        /// <returns>Array of random bytes.</returns>
        public byte[] NextBytes(int count)
        {
            var buffer = new byte[count];
            NextBytes(buffer, 0, count);
            return buffer;
        }

        /// <summary>
        ///     Generate and put random bytes in a buffer.
        /// </summary>
        /// <param name="buffer">Buffer to fill with random bytes.</param>
        public override sealed void NextBytes(byte[] buffer)
        {
            NextBytes(buffer, 0, buffer.Length);
        }

        /// <summary>
        ///     Generate and put random bytes in a buffer.
        /// </summary>
        /// <param name="buffer">Buffer to put random bytes in.</param>
        /// <param name="offset">Offset in buffer to put bytes in.</param>
        /// <param name="count">Number of bytes to return.</param>
        public abstract void NextBytes(byte[] buffer, int offset, int count);
    }
}
