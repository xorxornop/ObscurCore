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
using ObscurCore.Cryptography.Ciphers.Information;
using ObscurCore.DTO;
using PerfCopy;

namespace ObscurCore.Cryptography.Ciphers.Stream
{
    /// <summary>
    ///     Wraps a <see cref="CipherConfiguration" /> describing a stream cipher configuration,
    ///     and provides validation for its values.
    /// </summary>
    public class StreamCipherConfigurationWrapper : CipherConfigurationWrapper
    {
        public StreamCipherConfigurationWrapper(CipherConfiguration config) : base(config)
        {
            if (config == null) {
                throw new ArgumentNullException("config");
            }
            if (config.Type == CipherType.None) {
                throw new ConfigurationInvalidException("Cipher configuration specifies Type = None.");
            }
            if (config.Type != CipherType.Stream) {
                throw new ArgumentException("Configuration is not for a stream cipher.");
            }
        }

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
        ///     Nonces are sometimes called an initialisation vector, 
        ///     although nonce is nearly always the correct term for stream ciphers.
        ///     They should not be reused when used with a given key (as their name suggests),
        ///     as it frequently results in total loss of security properties.
        /// </remarks>
        public byte[] Nonce
        {
            get
            {
                StreamCipherInformation athenaInfo = Athena.Cryptography.StreamCiphers[StreamCipher];

                if (athenaInfo.DefaultNonceSizeBits == -1 && Configuration.InitialisationVector.IsNullOrZeroLength() == false) {
                    throw new ConfigurationInvalidException(
                        "NCipherKeySizeExceptiontion vector) should not be used with the " + StreamCipher + " cipher.");
                }
                if (athenaInfo.IsNonceSizeInSpecification(Configuration.InitialisationVector.Length * 8) == false) {
                    throw new ConfigurationInvalidException(
                        "Nonce (initialisation vector) size is not supported by the cipher specification.");
                }

                return Configuration.InitialisationVector == null ? null : Configuration.InitialisationVector.DeepCopy();
            }
            set { Configuration.InitialisationVector = value; }
        }

        protected override void ThrowIfKeySizeIncompatible()
        {
            if (Athena.Cryptography.StreamCiphers[StreamCipher].AllowableKeySizesBits.Contains(Configuration.KeySizeBits) ==
                false) {
                throw new CipherKeySizeException(StreamCipher, Configuration.KeySizeBits);
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
