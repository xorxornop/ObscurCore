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
using ObscurCore.DTO;
using ObscurCore.Information;

namespace ObscurCore.Cryptography.Ciphers.Stream
{
    public class StreamCipherConfigurationWrapper : CipherConfigurationWrapper
    {
        public StreamCipherConfigurationWrapper(CipherConfiguration config) : base(config) {}

        /// <summary>
        ///     Stream cipher to be used e.g. Salsa20, HC-128, etc.
        /// </summary>
        public StreamCipher StreamCipher
        {
            get
            {
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
        ///     Number-used-once for the cipher.
        /// </summary>
        /// <remarks>
        ///     Nonces are sometimes called an initialisation vector, although nonce is more accurate for stream ciphers.
        ///     They should not be reused when used with a given key (as their name suggests),
        ///     as it frequently results in total loss of security properties.
        /// </remarks>
        public byte[] Nonce
        {
            get
            {
                SymmetricCipherDescription athenaInfo = Athena.Cryptography.StreamCiphers[StreamCipher];

                if (athenaInfo.DefaultIvSize == -1 && Configuration.IV.IsNullOrZeroLength() == false) {
                    throw new ConfigurationInvalidException(
                        "Nonce (initialisation vector) should not be used with the " + StreamCipher + " cipher.");
                }
                if (athenaInfo.AllowableIvSizes.Contains(Configuration.IV.Length * 8) == false) {
                    throw new ConfigurationInvalidException(
                        "Nonce (initialisation vector) should not be a different length to the block size.");
                }

                return Configuration.IV == null ? null : Configuration.IV.DeepCopy();
            }
            set { Configuration.IV = value; }
        }

        protected override void ThrowIfKeySizeIncompatible()
        {
            if (Athena.Cryptography.StreamCiphers[StreamCipher].AllowableKeySizes.Contains(Configuration.KeySizeBits) ==
                false) {
                throw new KeySizeException(StreamCipher, Configuration.KeySizeBits);
            }
        }

        /// <summary>
        ///     Outputs a summary of the configuration, optionally including the nonce.
        /// </summary>
        /// <param name="includeValues">Whether to include values of relevant byte arrays as hex strings.</param>
        public override string ToString(bool includeValues)
        {
            string cipher = Athena.Cryptography.StreamCiphers[StreamCipher].DisplayName;
            if (includeValues) {
                return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                                     "Nonce: {3}",
                    CipherType.Stream, cipher, KeySizeBits, Nonce.IsNullOrZeroLength() ? "none" : Nonce.ToHexString());
            }
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}",
                CipherType.Stream, cipher, KeySizeBits);
        }
    }
}
