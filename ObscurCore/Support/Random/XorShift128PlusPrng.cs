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

namespace ObscurCore.Support.Random
{
    public sealed class XorShift128PlusPrng : XorShiftPrng
    {
        private const int ArrayStateSize = 2;

        public XorShift128PlusPrng(ulong[] seed = null)
            : base(ArrayStateSize, seed) {}

        public XorShift128PlusPrng(byte[] seed)
            : base(ArrayStateSize, seed) {}

        protected override ulong Generate()
        {
            ulong s1 = S[0];
            ulong s0 = S[1];
            S[0] = s0;
            s1 ^= s1 << 23; // a
            S[1] = (s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26));
            ulong ul = S[1] + s0; // b, c
            return ul;
        }
    }
}
