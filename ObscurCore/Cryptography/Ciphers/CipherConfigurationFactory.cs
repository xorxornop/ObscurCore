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
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Information;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    ///     Factory for <see cref="CipherConfiguration" /> data transfer objects,
    ///     used for configuring the operation of ciphers in a <see cref="CipherStream" />.
    /// </summary>
    public static class CipherConfigurationFactory
    {
        /// <summary>
        /// Create a configuration for a block cipher.
        /// </summary>
        /// <param name="cipher">Block cipher to use.</param>
        /// <param name="mode">Mode of operation for the cipher.</param>
        /// <param name="padding">Padding scheme to use with the mode, where necessary (e.g. CBC).</param>
        /// <param name="keySize">Key size to use, in bits.</param>
        /// <param name="blockSize">Cipher block size to use, in bits.</param>
        /// <returns>Block cipher configuration DTO.</returns>
        public static CipherConfiguration CreateBlockCipherConfiguration(BlockCipher cipher,
            BlockCipherMode mode, BlockCipherPadding padding, int? keySize = null, int? blockSize = null)
        {
            var config = new CipherConfiguration { Type = CipherType.Block };

            // Set the key size
            int keySizeNonNull = keySize ?? Athena.Cryptography.BlockCiphers[cipher].DefaultKeySize;
            if (keySize == null || Athena.Cryptography.BlockCiphers[cipher].AllowableKeySizes.Contains(keySizeNonNull)) {
                config.KeySizeBits = keySizeNonNull;
            } else {
                throw new CipherKeySizeException(cipher, keySizeNonNull);
            }

            // Set the block size
            int blockSizeNonNull = blockSize ?? Athena.Cryptography.BlockCiphers[cipher].DefaultBlockSize;
            if (blockSize == null ||
                Athena.Cryptography.BlockCiphers[cipher].AllowableBlockSizes.Contains(blockSizeNonNull)) {
                config.BlockSizeBits = blockSizeNonNull;
            } else {
                throw new BlockSizeException(cipher, blockSizeNonNull);
            }

            // Set the mode
            if (Athena.Cryptography.BlockCipherModes[mode].PaddingRequirement == PaddingRequirement.Always &&
                padding == BlockCipherPadding.None) {
                throw new ArgumentException(mode +
                                            " mode must be used with padding or errors will occur when plaintext length is not equal to or a multiple of the block size.");
            }

            config.ModeName = mode.ToString();
            config.PaddingName = padding.ToString();
            config.CipherName = cipher.ToString();

            config.InitialisationVector = new byte[config.BlockSizeBits.Value / 8];
            StratCom.EntropySupplier.NextBytes(config.InitialisationVector);

            return config;
        }

        /// <summary>
        ///     Create a configuration for a stream cipher.
        /// </summary>
        /// <param name="cipher">Stream cipher to use.</param>
        /// <param name="keySize">Key size to use, in bits.</param>
        /// <returns>Stream cipher configuration DTO.</returns>
        public static CipherConfiguration CreateStreamCipherConfiguration(StreamCipher cipher, int? keySize = null)
        {
            var config = new CipherConfiguration { Type = CipherType.Stream };

            int keySizeNonNull = keySize ?? Athena.Cryptography.StreamCiphers[cipher].DefaultKeySize;
            if (keySize == null || Athena.Cryptography.StreamCiphers[cipher].AllowableKeySizes.Contains(keySizeNonNull)) {
                config.KeySizeBits = keySizeNonNull;
            } else {
                throw new CipherKeySizeException(cipher, keySizeNonNull);
            }
            config.CipherName = cipher.ToString();

            if (Athena.Cryptography.StreamCiphers[cipher].DefaultNonceSize != -1) {
                config.InitialisationVector = new byte[Athena.Cryptography.StreamCiphers[cipher].DefaultNonceSize / 8];
                StratCom.EntropySupplier.NextBytes(config.InitialisationVector);
            }

            return config;
        }
    }
}
