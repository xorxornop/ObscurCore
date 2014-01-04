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
    public class BlockCipherConfigurationWrapper : SymmetricCipherConfigurationWrapper
    {
        public BlockCipherConfigurationWrapper(SymmetricCipherConfiguration config) : base(config) {}

        protected override void ThrowIfKeySizeIncompatible() {
            if (!Athena.Cryptography.BlockCiphers[BlockCipher].AllowableKeySizes.Contains(Configuration.KeySizeBits)) {
                throw new KeySizeException(BlockCipher, Configuration.KeySizeBits);
            }
        }

        /// <summary>
        /// Name of the cryptographic block cipher transform being used e.g. AES, Blowfish, etc.
        /// </summary>
        public SymmetricBlockCipher BlockCipher
        {
            get {
                SymmetricBlockCipher blockCipherEnum;
                try {
                    blockCipherEnum = Configuration.CipherName.ToEnum<SymmetricBlockCipher>();
                } catch (EnumerationValueUnknownException e) {
					throw new ConfigurationValueInvalidException("Cipher unknown/unsupported.", e);
                }
                return blockCipherEnum;
            }
            set { RawConfiguration.CipherName = value.ToString(); }
        }

        /// <summary>
        /// Mode of operation of the block cipher being used, e.g. CBC, CTR, OFB, etc.
        /// </summary>
        public BlockCipherMode Mode
        {
            get { return RawConfiguration.ModeName.ToEnum<BlockCipherMode>(); }
            set { RawConfiguration.ModeName = value.ToString(); }
        }

        /// <summary>
        /// Scheme utillised to 'pad' blocks to full size where required. 
        /// What any unused space in a block is filled with. 
        /// Set to empty if using block cipher in streaming mode.
        /// </summary>
        public BlockCipherPadding Padding
        {
            get {
                var paddingEnum = RawConfiguration.PaddingName.ToEnum<BlockCipherPadding>();
                if (!Athena.Cryptography.BlockCipherModes[Mode].PaddingRequirement.Equals(PaddingRequirement.None) && paddingEnum == BlockCipherPadding.None) {
					throw new ConfigurationInvalidException("Block cipher mode requires padding."); // TODO: make new custom exception
                }
                return paddingEnum;
            }
            set { RawConfiguration.PaddingName = value.ToString(); }
        }

        public int BlockSizeBits
        {
            get {
                if (Configuration.BlockSizeBits == 0) {
					throw new ConfigurationValueInvalidException("Block cipher cannot have a block size of 0 (zero).");
                }
                ThrowIfBlockSizeIncompatible();
                return RawConfiguration.BlockSizeBits;
            }
            set { RawConfiguration.BlockSizeBits = value; }
        }

		public int BlockSizeBytes
		{
			get { return BlockSizeBits / 8; }
			set { BlockSizeBits = value * 8; }
		}

        protected void ThrowIfBlockSizeIncompatible() {
            if (!Athena.Cryptography.BlockCiphers[BlockCipher].AllowableBlockSizes.Contains(Configuration.BlockSizeBits)) {
                throw new BlockSizeException(BlockCipher, Configuration.BlockSizeBits);
            }
        }

        public byte[] IV
        {
            get {
                if (Configuration.IV.IsNullOrZeroLength()) {
					throw new ConfigurationValueInvalidException("Block cipher cannot have an initalisation vector (IV) of null or zero length.");
                }
                if (Configuration.IV.Length != BlockSizeBits / 8) {
					throw new ConfigurationInvalidException("Initialisation vector should not be a different length to the block size.");
                }
                var retVal = new byte[Configuration.IV.Length];
                Buffer.BlockCopy(Configuration.IV, 0, retVal, 0, Configuration.IV.Length);
                return retVal;
            }
            set { RawConfiguration.IV = value; }
        }

        /// <summary>
        /// Outputs a summary of the configuration, optionally including the actual values of IV and Salt.
        /// </summary>
        /// <param name="includeValues">Whether to include values of relevant byte arrays as hex strings.</param>
        /// <returns></returns>
        public override string ToString(bool includeValues)
        {
            var cipher = Athena.Cryptography.BlockCiphers[BlockCipher].DisplayName;
            var mode = Athena.Cryptography.BlockCipherModes[Mode].DisplayName;
            var padding = Padding == BlockCipherPadding.None
                ? "None"
                : Athena.Cryptography.BlockCipherPaddings[Padding].DisplayName;
            if (includeValues)
            {
                var hexIV = IV.ToHexString();
                return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                    "Block size, bits: {3}\nMode: {4}\nPadding: {5}\n" +
                    "IV, hex: {6}",
                    SymmetricCipherType.Block, cipher, KeySizeBits, BlockSizeBits, mode, padding, hexIV);
            }
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                "Block size, bits: {3}\nMode: {4}\nPadding: {5}",
                SymmetricCipherType.Block, cipher, KeySizeBits, BlockSizeBits, mode, padding);
        }
    }
}