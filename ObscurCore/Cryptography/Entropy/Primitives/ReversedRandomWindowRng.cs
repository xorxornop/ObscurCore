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
using ObscurCore.Support.Random;

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
        private readonly Rng _rng;

        private readonly int _maxWindowSize;

        public ReversedRandomWindowRng(
            Rng rng,
            int maxWindowSize)
        {
            if (rng == null) {
                throw new ArgumentNullException("rng");
            }
            if (maxWindowSize < 2) {
                throw new ArgumentException("Maximum window size must be at least 2", "maxWindowSize");
            }

            _rng = rng;
            _maxWindowSize = maxWindowSize;
        }

        public Rng BaseRng
        {
            get { return _rng; }
        }

        /// <inheritdoc />
        public override void AddSeedMaterial(
            byte[] seed)
        {
            var rng = _rng as CsRng;
            if (rng != null) {
                lock (this) {
                    rng.AddSeedMaterial(seed);
                }
            } else {
                throw new InvalidOperationException("CSRNG was initialised with RNG, not CSRNG. Cannot add seed material.");
            }
        }

        /// <inheritdoc />
        public override void NextBytes(
            byte[] buffer,
            int offset,
            int count)
        {
            lock (this) {
                _rng.NextBytes(buffer, offset, count);
                var maxWindow = Math.Min(count, _maxWindowSize);
                var windowOffset = _rng.Next(maxWindow + 1);
                var windowSize = _rng.Next(count - windowOffset);
                Array.Reverse(buffer, offset + windowOffset, windowSize);
            }
        }
    }
}
