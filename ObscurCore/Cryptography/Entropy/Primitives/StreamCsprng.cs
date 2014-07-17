//
//  Copyright 2013  Matthew Ducker
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
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
    public class StreamCsprng : CsPrng
    {
        protected readonly ICsprngCompatible Csprng;

        public StreamCsprng(IStreamCipher cipher, StreamCipherCsprngConfiguration config) 
            : base(cipher.StateSize)
        {
            Csprng = cipher as ICsprngCompatible;
            if (Csprng == null) {
                throw new ArgumentException();
            }
            cipher.Init(true, config.Key, config.Nonce);
        }

        public StreamCsprng(IStreamCipher cipher, byte[] configBytes)
            : base(cipher.StateSize)
        {
            Csprng = cipher as ICsprngCompatible;
            if (Csprng == null) {
                throw new ArgumentException();
            }
            var configObj = configBytes.DeserialiseDto<StreamCipherCsprngConfiguration>();
            cipher.Init(true, configObj.Key, configObj.Nonce);
        }

        protected internal IStreamCipher Cipher
        {
            get { return Csprng as IStreamCipher; }
        }

        public static StreamCipherCsprngConfiguration CreateRandomConfiguration(CsPseudorandomNumberGenerator csprng)
        {
            var cipherEnum = csprng.ToString().ToEnum<StreamCipher>();
            var config = new StreamCipherCsprngConfiguration {
                CipherName = csprng.ToString(),
                Key = new byte[Athena.Cryptography.StreamCiphers[cipherEnum].DefaultKeySize / 8],
                Nonce = new byte[Athena.Cryptography.StreamCiphers[cipherEnum].DefaultNonceSize / 8]
            };
            StratCom.EntropySupplier.NextBytes(config.Key);
            StratCom.EntropySupplier.NextBytes(config.Nonce);
            return config;
        }

        protected override void NextState()
        {
            byte[] buf = new byte[StateSize];
            Csprng.GetKeystream(buf, 0, StateSize);
            StateBuffer.Put(buf);
        }

        protected override void GetNextState(byte[] buffer, int offset)
        {
            Csprng.GetKeystream(buffer, offset, StateSize);
        }

        public override void Reset()
        {
            ((IStreamCipher)Csprng).Reset();
        }
    }
}
