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
using ObscurCore.Support.Entropy;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
    /// <summary>
    ///     Reverses the order of bytes within a window of output (of configurable size) 
    ///     from another CSRNG.
    /// </summary>
    /// <remarks>
    ///     Access to internals is synchronised so a single instance can be shared.
    /// </remarks>
    public sealed class ReversedRandomWindowRng : CsRng
    {
        private readonly CsRng _csRng;

        private readonly int _maxWindowSize;

        public ReversedRandomWindowRng(
            CsRng csRng,
            int maxWindowSize)
        {
            if (csRng == null) {
                throw new ArgumentNullException("csRng");
            }
            if (maxWindowSize < 2) {
                throw new ArgumentException("Maximum window size must be at least 2", "maxWindowSize");
            }

            _csRng = csRng;
            _maxWindowSize = maxWindowSize;
        }

        public Rng BaseCsRng
        {
            get { return _csRng; }
        }

        /// <inheritdoc />
        public override void AddSeedMaterial(
            byte[] seed)
        {
            lock (this) {
                _csRng.AddSeedMaterial(seed);
            }
        }

        /// <inheritdoc />
        public override void NextBytes(
            byte[] buffer,
            int offset,
            int count)
        {
            lock (this) {
                _csRng.NextBytes(buffer, offset, count);
                var maxWindow = Math.Min(count, _maxWindowSize);
                var windowOffset = _csRng.Next(maxWindow + 1);
                var windowSize = _csRng.Next(count - windowOffset);
                Array.Reverse(buffer, offset + windowOffset, windowSize);
            }
        }
    }
}
