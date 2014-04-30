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
using System.Linq;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Ciphers.Stream
{
    public class StreamCipherConfigurationWrapper : CipherConfigurationWrapper
    {
        public StreamCipherConfigurationWrapper(CipherConfiguration config) : base(config) {}

        protected override void ThrowIfKeySizeIncompatible() {
            if (!Athena.Cryptography.StreamCiphers[StreamCipher].AllowableKeySizes.Contains(Configuration.KeySizeBits)) {
                throw new KeySizeException(StreamCipher, Configuration.KeySizeBits);
            }
        }

        /// <summary>
        /// Name of the cryptographic stream cipher transform being used e.g. Salsa20, VMPC, etc.
        /// </summary>
        public StreamCipher StreamCipher
        {
            get {
                StreamCipher streamCipherEnum;
                try {
                    streamCipherEnum = Configuration.CipherName.ToEnum<StreamCipher>();
                } catch (EnumerationParsingException e) {
                    throw new ConfigurationInvalidException("Cipher unknown/unsupported.", e);
                }
                return streamCipherEnum;
            }
            set { Configuration.CipherName = value.ToString(); }
        }

        /// <summary>
        /// Number-used-once.
        /// </summary>
        public byte[] Nonce
        {
            get {
                return Configuration.IV == null ? null : Configuration.IV.DeepCopy();
            }
            set { Configuration.IV = value; }
        }

        public override string ToString(bool includeValues)
        {
            var cipher = Athena.Cryptography.StreamCiphers[StreamCipher].DisplayName;
            if (includeValues)
            {
                return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                    "Nonce, hex: {3}",
					CipherType.Stream, cipher, KeySizeBits, Nonce.IsNullOrZeroLength() ? "none" : Nonce.ToHexString());
            }
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}",
					CipherType.Stream, cipher, KeySizeBits);
        }
    }
}
