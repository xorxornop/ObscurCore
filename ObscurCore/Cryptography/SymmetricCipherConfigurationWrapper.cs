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
using ObscurCore.DTO;

namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Provides access to underlying DTO object while validating input/output.
    /// </summary>
    public abstract class SymmetricCipherConfigurationWrapper
    {
        protected readonly SymmetricCipherConfiguration Configuration;

        protected SymmetricCipherConfigurationWrapper(SymmetricCipherConfiguration config) {
            Configuration = config;
        }

        public SymmetricCipherConfiguration RawConfiguration {
            get { return Configuration; }
        }

        public int KeySizeBits 
        {
            get {
                if (Configuration.KeySizeBits == 0) {
					throw new ConfigurationValueInvalidException("Cipher cannot have a key size of 0 (zero).");
                }
                if (!Configuration.Key.IsNullOrZeroLength() &&
					Configuration.Key.Length != Configuration.KeySizeBits / 8) {
                    throw new KeySizeException("Key size inconsistent with actual key length.");
                }
                ThrowIfKeySizeIncompatible();
                return Configuration.KeySizeBits;
            }
            set { Configuration.KeySizeBits = value; }
        }

        /// <summary>
        /// Size of the key in bytes.
        /// </summary>
        /// <exception cref="ConfigurationException">Key size is zero.</exception>
        /// <exception cref="KeySizeException">Key is not size specified by KeySizeBits or is incompatible with cipher.</exception>
        public int KeySizeBytes
        {
            get { return KeySizeBits / 8; }
			set { Configuration.KeySizeBits = value * 8; }
        }

        /// <summary>
        /// Check if key size is compatible with the cipher.
        /// </summary>
        /// <exception cref="KeySizeException">
        /// Key is incompatible with cipher.
        /// </exception>
        protected abstract void ThrowIfKeySizeIncompatible();

        public byte[] Key
        {
            get {
                var retVal = new byte[Configuration.Key.Length];
                Buffer.BlockCopy(Configuration.Key, 0, retVal, 0, Configuration.Key.Length);
                return retVal;
            }
            set { Configuration.Key = value; }
        }

        public override string ToString()
        {
            return ToString(false);
        }

        public abstract string ToString(bool includeValues);
    }
}