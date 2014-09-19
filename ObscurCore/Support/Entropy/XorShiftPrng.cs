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

namespace ObscurCore.Support.Entropy
{
    public abstract class XorShiftPrng : Prng
    {
        protected ulong[] S;

        protected XorShiftPrng(int stateSize, ulong[] seed)
            : base(sizeof (UInt64))
        {
            if (stateSize < 2) {
                throw new ArgumentOutOfRangeException("stateSize");
            }
            if (seed != null) {
                if (seed.Length != stateSize) {
                    throw new ArgumentException("Seed incorrect length.", "seed");
                }
                S = seed.DeepCopy();
            } else {
                S = new ulong[stateSize];
            }
        }

        protected XorShiftPrng(int stateSize, byte[] seed)
            : base(sizeof (UInt64))
        {
            if (stateSize < 2) {
                throw new ArgumentOutOfRangeException("stateSize");
            }
            S = new ulong[stateSize];
            if (seed != null) {
                if (seed.Length != stateSize * sizeof (ulong)) {
                    throw new ArgumentException("Seed incorrect length.", "seed");
                }
                for (int i = 0; i < stateSize; i++) {
                    S[i] = seed.LittleEndianToUInt64(i * sizeof (ulong));
                }
            }
        }

        protected abstract ulong Generate();

        /// <inheritdoc />
        protected override void NextState()
        {
            StateBuffer.Put(Generate().ToLittleEndian());
        }

        /// <inheritdoc />
        protected override void GetNextState(byte[] buffer, int offset)
        {
            Generate().ToLittleEndian(buffer, offset);
        }
    }
}
