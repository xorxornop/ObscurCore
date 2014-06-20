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

namespace ObscurCore.Cryptography.Entropy
{
    public abstract class StreamCsprng : Csprng
    {
        protected readonly ICsprngCompatible Csprng;
        private readonly StreamCipherCsprngConfiguration _config;

        protected StreamCsprng(IStreamCipher cipher, StreamCipherCsprngConfiguration config)
        {
            Csprng = cipher as ICsprngCompatible;
            if (Csprng == null) {
                throw new ArgumentException();
            }
            _config = config;
        }

        protected StreamCsprng(IStreamCipher cipher, byte[] configBytes)
        {
            Csprng = cipher as ICsprngCompatible;
            if (Csprng == null) {
                throw new ArgumentException();
            }

            _config = StratCom.DeserialiseDataTransferObject<StreamCipherCsprngConfiguration>(configBytes);
        }

        protected internal IStreamCipher Cipher
        {
            get { return Csprng as IStreamCipher; }
        }

        protected internal StreamCipherCsprngConfiguration Config
        {
            get { return _config; }
        }

        public static StreamCipherCsprngConfiguration CreateRandomConfiguration(CsPseudorandomNumberGenerator csprng)
        {
            var cipherEnum = csprng.ToString().ToEnum<StreamCipher>();
            var config = new StreamCipherCsprngConfiguration {
                CipherName = csprng.ToString(),
                Key = new byte[Athena.Cryptography.StreamCiphers[cipherEnum].DefaultKeySize / 8],
                Nonce = new byte[Athena.Cryptography.StreamCiphers[cipherEnum].DefaultIvSize / 8]
            };
            StratCom.EntropySupplier.NextBytes(config.Key);
            StratCom.EntropySupplier.NextBytes(config.Nonce);
            return config;
        }

        public override void NextBytes(byte[] buffer)
        {
            Csprng.GetKeystream(buffer, 0, buffer.Length);
        }
    }
}
