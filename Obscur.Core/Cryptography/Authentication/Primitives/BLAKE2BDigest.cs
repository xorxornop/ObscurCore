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
using PerfCopy;

namespace Obscur.Core.Cryptography.Authentication.Primitives
{
    public class Blake2BDigest : HashEngine
    {
        private static readonly Blake2BCore.Blake2BConfig DefaultConfig = new Blake2BCore.Blake2BConfig();
        private readonly Blake2BCore _core = new Blake2BCore();
        protected int HashSize;

        private byte[] _key;
        private ulong[] _rawConfig;

        public Blake2BDigest(int sizeInBits)
            : this(sizeInBits, true) {}

        protected Blake2BDigest(int sizeInBits, bool init)
            : base((HashFunction) Enum.Parse(typeof (HashFunction), "Blake2B" + sizeInBits))
        {
            HashSize = sizeInBits / 8;
            if (!init) {
                return;
            }

            var config = new Blake2BCore.Blake2BConfig {
                Key = null,
                Salt = null,
                Personalization = null,
                OutputSizeInBytes = sizeInBits / 8,
            };

            InitCore(config);
        }

        protected void InitCore(Blake2BCore.Blake2BConfig config)
        {
            Blake2BCore.Blake2BConfig cfg = config ?? DefaultConfig;
            _rawConfig = Blake2BCore.ConfigB(cfg);
            if (cfg.Key.IsNullOrZeroLength() == false) {
                _key = new byte[128];
                cfg.Key.DeepCopy_NoChecks(0, _key, 0, cfg.Key.Length);
            }
            HashSize = cfg.OutputSizeInBytes;
            ResetCore();
        }

        #region HashEngine implementation

        public override int StateSize
        {
            get { return 128; }
        }

        protected internal override void UpdateInternal(byte input)
        {
            _core.HashCore(input);
        }

        public override void Reset()
        {
            ResetCore();
        }

        protected void ResetCore()
        {
            if (_rawConfig == null) {
                throw new InvalidOperationException();
            }
            _core.Initialize(_rawConfig);
            if (_key.IsNullOrZeroLength() == false) {
                _core.HashCore(_key, 0, _key.Length);
            }
        }

        /// <summary>
        ///     Process bytes from <paramref name="input" />.
        ///     Performs no checks on argument validity - use only when pre-validated!
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///     The offset in <paramref name="input" /> at which the input data begins.
        /// </param>
        /// <param name="length">The number of bytes to be processed.</param>
        protected internal override void BlockUpdateInternal(byte[] input, int inOff, int length)
        {
            _core.HashCore(input, inOff, length);
        }

        /// <summary>
        ///     Compute and output the final state, and reset the internal state of the hash function.
        ///     Performs no checks on argument validity - use only when pre-validated!
        /// </summary>
        /// <param name="output">Array that the hash is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output" /> that the output is to start at.
        /// </param>
        /// <exception cref="InvalidOperationException">The hash function is not initialised.</exception>
        /// <returns>Size of the output in bytes.</returns>
        protected internal override int DoFinalInternal(byte[] output, int outOff)
        {
            _core.HashFinal(output, outOff, HashSize);
            Reset();
            return OutputSize;
        }

        #endregion
    }
}
