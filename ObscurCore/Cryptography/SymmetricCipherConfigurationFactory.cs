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
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;
using ObscurCore.Information;

namespace ObscurCore.Cryptography
{
    public static class SymmetricCipherConfigurationFactory
    {
        public static SymmetricCipherConfiguration CreateBlockCipherConfiguration(SymmetricBlockCipher cipher,
        	BlockCipherMode mode, BlockCipherPadding padding, int? keySize = null, int? blockSize = null)
        {
            var config = new SymmetricCipherConfiguration { Type = SymmetricCipherType.Block };

            // Set the key size
            var keySizeNonNull = keySize ?? Athena.Cryptography.BlockCiphers[cipher].DefaultKeySize;
            if (Athena.Cryptography.BlockCiphers[cipher].AllowableKeySizes.Contains(keySizeNonNull)) {
                config.KeySizeBits = keySizeNonNull;
            } else {
                throw new KeySizeException(cipher, keySizeNonNull);
            }

            // Set the block size
            var blockSizeNonNull = blockSize ?? Athena.Cryptography.BlockCiphers[cipher].DefaultBlockSize;
            if (Athena.Cryptography.BlockCiphers[cipher].AllowableBlockSizes.Contains(blockSizeNonNull)) {
                config.BlockSizeBits = blockSizeNonNull;
            } else {
                throw new BlockSizeException(cipher, blockSizeNonNull);
            }

            // Set the mode
            if (Athena.Cryptography.BlockCipherModes[mode].PaddingRequirement == PaddingRequirement.Always &&
                padding == BlockCipherPadding.None)
            {
                // TODO: Refine my logic!
                throw new ArgumentException(mode +
                    " mode must be used with padding or errors will occur when plaintext length is not equal to or a multiple of the block size.");
            }

            config.ModeName = mode.ToString();
            config.PaddingName = padding.ToString();
            config.CipherName = cipher.ToString();

            config.IV = new byte[config.BlockSizeBits / 8];
            StratCom.EntropySource.NextBytes(config.IV);

            return config;
        }

        public static SymmetricCipherConfiguration CreateStreamCipherConfiguration(SymmetricStreamCipher cipher,
        	int? keySize = null)
        {
            var config = new SymmetricCipherConfiguration {Type = SymmetricCipherType.Stream};

            var keySizeNonNull = keySize ?? Athena.Cryptography.StreamCiphers[cipher].DefaultKeySize;
            if (Athena.Cryptography.StreamCiphers[cipher].AllowableKeySizes.Contains(keySizeNonNull)) {
                config.KeySizeBits = keySizeNonNull;
            } else {
                throw new KeySizeException(cipher, keySizeNonNull);
            }
            config.CipherName = cipher.ToString();
            if(Athena.Cryptography.StreamCiphers[cipher].DefaultIvSize != -1) 
                config.IV = new byte[Athena.Cryptography.StreamCiphers[cipher].DefaultIvSize / 8];

            StratCom.EntropySource.NextBytes(config.IV);

            return config;
        }
    }
}