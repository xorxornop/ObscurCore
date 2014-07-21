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
using RingByteBuffer;

namespace ObscurCore.Support.Random
{
    /// <summary>
    ///     Base class for pseudorandom number generators (PRNGs).
    /// </summary>
    /// <remarks>
    ///     All generators deriving from this must operate deterministically.
    /// </remarks>
    public abstract class Prng : Rng
    {
        protected readonly int StateSize;
        protected readonly RingBuffer StateBuffer;

        protected Prng(int stateSize)
        {
            StateSize = stateSize;
            StateBuffer = new RingBuffer(stateSize);
        }

        /// <summary>
        /// Advance the state of the internal pseudorandom function, and store it in the StateBuffer.
        /// </summary>
        protected abstract void NextState();

        /// <summary>
        /// Advance the state of the internal pseudorandom function, and return it directly.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        protected abstract void GetNextState(byte[] buffer, int offset);

        /// <inheritdoc />
        public override void NextBytes(byte[] buffer, int offset, int count)
        {
            int length = count;
            int sbLength = Math.Min(StateBuffer.Length, count);
            StateBuffer.Take(buffer, offset, sbLength);
            offset += sbLength;
            length -= sbLength;

            int rem;
            int ops = Math.DivRem(length, StateSize, out rem);
            for (int i = 0; i < ops; i++) {
                GetNextState(buffer, offset + (i * StateSize));
            }
            if (rem > 0) {
                NextState();
                StateBuffer.Take(buffer, buffer.Length - rem, rem);
            }
        }

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
    }
}
