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
using Obscur.Core.Cryptography.Ciphers.Stream;
using Obscur.Core.DTO;

namespace Obscur.Core.Cryptography.Entropy.Primitives
{
    public sealed class StreamCsPrng : CsPrng
    {
        private readonly ICsPrngCompatible _csPrng;
        private byte[] _stateBuf;

        public StreamCsPrng(StreamCipherEngine cipher, byte[] key, byte[] nonce)
            : base(cipher.StateSize)
        {
            _csPrng = cipher as ICsPrngCompatible;
            if (_csPrng == null) {
                throw new ArgumentException();
            }
            _stateBuf = new byte[StateSize];
            cipher.Init(true, key, nonce);
        }

        internal StreamCipherEngine Cipher
        {
            get { return _csPrng as StreamCipherEngine; }
        }

        public static StreamCipherCsprngConfiguration CreateRandomConfiguration(CsPseudorandomNumberGenerator csprng)
        {
            var cipherEnum = csprng.ToString().ToEnum<StreamCipher>();
            var config = new StreamCipherCsprngConfiguration {
                CipherName = csprng.ToString(),
                Key = new byte[Athena.Cryptography.StreamCiphers[cipherEnum].DefaultKeySizeBits / 8],
                Nonce = new byte[Athena.Cryptography.StreamCiphers[cipherEnum].DefaultNonceSizeBits / 8]
            };
            StratCom.EntropySupplier.NextBytes(config.Key);
            StratCom.EntropySupplier.NextBytes(config.Nonce);
            return config;
        }

        /// <inheritdoc />
        protected override void NextState()
        {
            _csPrng.GetKeystream(_stateBuf, 0, StateSize);
            StateBuffer.Put(_stateBuf);
        }

        /// <inheritdoc />
        protected override void GetNextState(byte[] buffer, int offset)
        {
            _csPrng.GetKeystream(buffer, offset, StateSize);
        }

        /// <inheritdoc />
        public override void Reset()
        {
            ((StreamCipherEngine) _csPrng).Reset();
        }
    }
}
