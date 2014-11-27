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
using Obscur.Core.Support.Entropy;

namespace Obscur.Core.Cryptography.Entropy.Primitives
{
    /// <summary>
    ///     Reverses the order of bytes within a window of output (of configurable size)
    ///     from another CSRNG.
    /// </summary>
    /// <remarks>
    ///     Access to internals is synchronised so a single instance can be shared.
    /// </remarks>
    public sealed class ReversedWindowCsRng : CsRng
    {
        private readonly CsRng _csRng;

        private readonly byte[] _window;

        private int _windowCount;

        public ReversedWindowCsRng(
            CsRng csRng,
            int windowSize)
        {
            if (csRng == null) {
                throw new ArgumentNullException("csRng");
            }
            if (windowSize < 2) {
                throw new ArgumentException("Window size must be at least 2", "windowSize");
            }

            _csRng = csRng;
            _window = new byte[windowSize];
        }

        public Rng BaseCsRng
        {
            get { return _csRng; }
        }

        public override void AddSeedMaterial(
            byte[] seed)
        {
            lock (this) {
                _windowCount = 0;
                _csRng.AddSeedMaterial(seed);
            }
        }

        protected override CsRng CreateGenerator()
        {
            // TODO: Fix shitty implementation that doesn't really do anything useful except prevent build error
            return new ReversedWindowCsRng(_csRng, _windowCount);
        }

        public override void NextBytes(
            byte[] buffer,
            int offset,
            int count)
        {
            lock (this) {
                int done = 0;
                while (done < count) {
                    if (_windowCount < 1) {
                        _csRng.NextBytes(_window, 0, _window.Length);
                        _windowCount = _window.Length;
                    }
                    buffer[offset + done++] = _window[--_windowCount];
                }
            }
        }
    }
}
