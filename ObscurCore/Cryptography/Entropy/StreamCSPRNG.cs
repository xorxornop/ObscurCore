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

using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy
{
    public abstract class StreamCSPRNG : CSPRNG
    {
        protected IStreamCipher Cipher;
        protected StreamCipherCSPRNGConfiguration Config;

        protected StreamCSPRNG(StreamCipherCSPRNGConfiguration config) {
            Config = config;
        }

        protected StreamCSPRNG(byte[] configBytes) {
            var config = StratCom.DeserialiseDTO<StreamCipherCSPRNGConfiguration>(configBytes);
            Config = config;
        }

        public static StreamCipherCSPRNGConfiguration CreateRandomConfiguration(SymmetricStreamCiphers cipher) {
            var config = new StreamCipherCSPRNGConfiguration()
                {
                    CipherName = cipher.ToString(),
                    Key = new byte[Athena.Cryptography.StreamCipherDirectory[cipher].DefaultKeySize / 8],
                    Nonce = new byte[Athena.Cryptography.StreamCipherDirectory[cipher].DefaultIVSize / 8]
                };
            return config;
        }
    }
}
