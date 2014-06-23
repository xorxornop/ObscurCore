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

namespace ObscurCore.Cryptography.Ciphers.Block
{
    public class BlockCipherConfigurationWrapper : CipherConfigurationWrapper
    {
        public BlockCipherConfigurationWrapper(CipherConfiguration config) : base(config) {}

        /// <summary>
        ///     Block cipher to be used, e.g. AES, Twofish, etc.
        /// </summary>
        public BlockCipher BlockCipher
        {
            get
            {
                BlockCipher blockCipherEnum;
                try {
                    blockCipherEnum = Configuration.CipherName.ToEnum<BlockCipher>();
                } catch (EnumerationParsingException e) {
                    throw new ConfigurationInvalidException("Cipher unknown/unsupported.", e);
                }
                return blockCipherEnum;
            }
            set { RawConfiguration.CipherName = value.ToString(); }
        }

        /// <summary>
        ///     Mode of operation of the block cipher being used, e.g. CBC, CTR, OFB, etc.
        /// </summary>
        public BlockCipherMode Mode
        {
            get { return RawConfiguration.ModeName.ToEnum<BlockCipherMode>(); }
            set { RawConfiguration.ModeName = value.ToString(); }
        }

        /// <summary>
        ///     Scheme utillised to 'pad' blocks to full size where required.
        ///     What any unused space in a block is filled with.
        ///     Set to empty if using block cipher in streaming mode.
        /// </summary>
        public BlockCipherPadding Padding
        {
            get
            {
                var paddingEnum = RawConfiguration.PaddingName.ToEnum<BlockCipherPadding>();
                if (Athena.Cryptography.BlockCipherModes[Mode].PaddingRequirement.Equals(PaddingRequirement.None) ==
                    false &&
                    paddingEnum == BlockCipherPadding.None) {
                    throw new ConfigurationInvalidException("Block cipher mode requires padding.");
                        // TODO: make new custom exception
                }
                return paddingEnum;
            }
            set { RawConfiguration.PaddingName = value.ToString(); }
        }

        public int BlockSizeBits
        {
            get
            {
                if (Configuration.BlockSizeBits.HasValue == false) {
                    throw new ConfigurationInvalidException("Block cipher cannot have a block size of null.");
                }
                if (Configuration.BlockSizeBits == 0) {
                    throw new ConfigurationInvalidException("Block cipher cannot have a block size of 0 (zero).");
                }
                ThrowIfBlockSizeIncompatible();
                return RawConfiguration.BlockSizeBits.Value;
            }
            set { RawConfiguration.BlockSizeBits = value; }
        }

        public int BlockSizeBytes
        {
            get { return BlockSizeBits / 8; }
            set { BlockSizeBits = value * 8; }
        }

        /// <summary>
        ///     Initialisation vector (also called a nonce in this context, which is a specialised subset).
        /// </summary>
        /// <remarks>
        ///     Typically used by the mode of operation, rather than the cipher itself.
        ///     An IV ensures that if identical data and key is used twice, the resulting ciphertext is different (if a different
        ///     IV is used).
        ///     It is not a value usually required to be kept secret, although it can contribute additional security if it is.
        /// </remarks>
        public byte[] IV
        {
            get
            {
                if (Configuration.InitialisationVector.IsNullOrZeroLength()) {
                    throw new ConfigurationInvalidException(
                        "Block cipher cannot have an initalisation vector (IV) of null or zero length.");
                }
                if (Configuration.InitialisationVector.Length != BlockSizeBytes) {
                    throw new ConfigurationInvalidException(
                        "Initialisation vector should not be a different length to the block size.");
                }

                return Configuration.InitialisationVector.DeepCopy();
            }
            set { RawConfiguration.InitialisationVector = value; }
        }

        protected override void ThrowIfKeySizeIncompatible()
        {
            if (Athena.Cryptography.BlockCiphers[BlockCipher]
                .AllowableKeySizes.Contains(Configuration.KeySizeBits) == false) 
            {
                throw new KeySizeException(BlockCipher, Configuration.KeySizeBits);
            }
        }

        protected void ThrowIfBlockSizeIncompatible()
        {
            if (Athena.Cryptography.BlockCiphers[BlockCipher]
                .AllowableBlockSizes.Contains(Configuration.BlockSizeBits.Value) == false) 
            {
                throw new BlockSizeException(BlockCipher, Configuration.BlockSizeBits.Value);
            }
        }

        /// <summary>
        ///     Outputs a summary of the configuration, optionally including the IV.
        /// </summary>
        /// <param name="includeValues">Whether to include values of relevant byte arrays as hex strings.</param>
        public override string ToString(bool includeValues)
        {
            string cipher = Athena.Cryptography.BlockCiphers[BlockCipher].DisplayName;
            string mode = Athena.Cryptography.BlockCipherModes[Mode].DisplayName;
            string padding = Padding == BlockCipherPadding.None
                ? "None"
                : Athena.Cryptography.BlockCipherPaddings[Padding].DisplayName;
            if (includeValues) {
                return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                                     "Block size, bits: {3}\nMode: {4}\nPadding: {5}\n" +
                                     "IV: {6}",
                    CipherType.Block, cipher, KeySizeBits, BlockSizeBits, mode, padding, IV.ToHexString());
            }
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                                 "Block size, bits: {3}\nMode: {4}\nPadding: {5}",
                CipherType.Block, cipher, KeySizeBits, BlockSizeBits, mode, padding);
        }
    }
}
