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
    public sealed class XorShift1204StarPrng : XorShiftPrng
    {
        private const int ArrayStateSize = 16;
        private int _p;

        public XorShift1204StarPrng(ulong[] seed)
            : base(ArrayStateSize, seed) {}

        public XorShift1204StarPrng(byte[] seed)
            : base(ArrayStateSize, seed) {}

        protected override ulong Generate()
        {
            ulong s0 = S[_p];
            _p = (_p + 1) & 15;
            ulong s1 = S[_p];
            s1 ^= s1 << 31; // a
            s1 ^= s1 >> 11; // b
            s0 ^= s0 >> 30; // c
            S[_p] = s0 ^ s1;
            ulong ul = S[_p] * 1181783497276652981L;
            return ul;
        }
    }
}
