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
using ObscurCore.Extensions.ByteArrays;
using ObscurCore.Extensions.Enumerations;

namespace ObscurCore.Cryptography
{
    public static class SymmetricCipherConfigurationFactory
    {
        public static SymmetricCipherConfiguration CreateBlockCipherConfiguration(SymmetricBlockCiphers cipher,
                                                                                  BlockCipherModes mode,
                                                                                  BlockCipherPaddings padding,
                                                                                  int? blockSize = null,
                                                                                  int? keySize = null)
        {

            var config = new SymmetricCipherConfiguration {Type = SymmetricCipherType.Block};

            // Set the key size
            int keySizeNonNull = keySize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultKeySize;
            if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableKeySizes.Contains(keySizeNonNull)) {
                config.KeySize = keySizeNonNull;
            } else {
                throw new KeySizeException(keySizeNonNull,
                    Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName + " specification");
            }
            config.Key = new byte[config.KeySize];

             // Set the block size
            var blockSizeNonNull = blockSize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultBlockSize;
            // TODO: Add in a section to handle MAC and block sizes seperately.
            if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableBlockSizes.Contains(blockSizeNonNull)) {
                config.BlockSize = blockSizeNonNull;
            } else {
                throw new BlockSizeException(blockSizeNonNull,
                    Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName + " specification");
            }

            // Set the mode
            if (Athena.Cryptography.BlockCipherModeDirectory[mode].PaddingRequirement == PaddingRequirements.Always &&
                padding == BlockCipherPaddings.None)
            {
                // TODO: Refine my logic!
                throw new ArgumentException(mode +
                    " mode must be used with padding or errors will occur when plaintext length is not equal to or a multiple of the block size.");
            }

            config.ModeName = mode.ToString();
            config.PaddingName = padding.ToString();
            config.CipherName = cipher.ToString();

            // TODO: Review this code, make more resource efficient.
            config.IV = new byte[config.BlockSize / 8];
            StratCom.EntropySource.NextBytes(config.IV);

            return config;
        }

        public static SymmetricCipherConfiguration CreateAEADBlockCipherConfiguration(SymmetricBlockCiphers cipher,
                                                                                      AEADBlockCipherModes mode,
                                                                                      BlockCipherPaddings padding =
                                                                                          BlockCipherPaddings.None,
                                                                                      int? keySize = null,
                                                                                      int? blockSize = null,
                                                                                      int? macSize = null)
        {

            var config = new SymmetricCipherConfiguration {Type = SymmetricCipherType.AEAD};

            // Set the key size
            int keySizeNonNull = keySize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultKeySize;
            if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableKeySizes.Contains(keySizeNonNull)) {
                config.KeySize = keySizeNonNull;
            } else {
                throw new KeySizeException(keySizeNonNull,
                    Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName + " specification");
            }
            config.Key = new byte[config.KeySize];

            // Set the block size
            var blockSizeNonNull = blockSize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultBlockSize;
            // TODO: Add in a section to handle MAC and block sizes seperately.
            if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableBlockSizes.Contains(blockSizeNonNull)) {
                config.BlockSize = blockSizeNonNull;
            } else {
                throw new BlockSizeException(blockSizeNonNull,
                    Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName + " specification");
            }

            // Set the mode
            if (Athena.Cryptography.AEADBlockCipherModeDirectory[mode].PaddingRequirement == PaddingRequirements.Always &&
                padding == BlockCipherPaddings.None) // TODO: Refine my logic!
            {
                throw new ArgumentException(mode +
                    " mode must be used with padding or errors will occur when plaintext length is not equal to or a multiple of the block size.");
            }
            // Check if the AEAD mode supports the block size
            int macSizeNonNull = macSize ?? config.BlockSize;
            if (!Athena.Cryptography.AEADBlockCipherModeDirectory[mode].AllowableBlockSizes.Contains(-1))
            {
                if (Athena.Cryptography.AEADBlockCipherModeDirectory[mode].AllowableBlockSizes.Contains(config.BlockSize))
                    config.MACSize = macSizeNonNull;
                else
                    throw new MACSizeException(macSizeNonNull,
                        Athena.Cryptography.AEADBlockCipherModeDirectory[mode].DisplayName +
                            " specification");
            }

            config.ModeName = mode.ToString();
            config.PaddingName = padding.ToString();
            config.CipherName = cipher.ToString();
            // TODO: Review this code, make more resource efficient.
            config.IV = new byte[config.BlockSize / 8]; // Nonce in AEAD
            StratCom.EntropySource.NextBytes(config.IV);

            return config;
        }

        public static SymmetricCipherConfiguration CreateStreamCipherConfiguration(SymmetricStreamCiphers cipher,
                                                                                   int? keySize = null)
        {
            var config = new SymmetricCipherConfiguration {Type = SymmetricCipherType.Stream};

            var keySizeNonNull = keySize ?? Athena.Cryptography.StreamCipherDirectory[cipher].DefaultKeySize;
            if (Athena.Cryptography.StreamCipherDirectory[cipher].AllowableKeySizes.Contains(keySizeNonNull)) {
                config.KeySize = keySizeNonNull;
            } else {
                throw new KeySizeException(keySizeNonNull,
                    Athena.Cryptography.StreamCipherDirectory[cipher].DisplayName + " specification");
            }
            config.Key = new byte[config.KeySize];
            config.CipherName = cipher.ToString();
            if(Athena.Cryptography.StreamCipherDirectory[cipher].DefaultIVSize != -1) 
                config.IV = new byte[Athena.Cryptography.StreamCipherDirectory[cipher].DefaultIVSize / 8];

            StratCom.EntropySource.NextBytes(config.IV);

            return config;
        }
    }

    public abstract class SymmetricCipherConfigurationWrapper
    {
        protected SymmetricCipherConfiguration Config;

        public int KeySize
        {
            get { return Config.KeySize; }
            set { Config.KeySize = value; }
        }

        public byte[] Key
        {
            get { return Config.Key; }
            set { Config.Key = value; }
        }

        public override string ToString()
        {
            return ToString(false);
        }

        public abstract string ToString(bool includeValues);
    }

    public class BlockCipherConfigurationWrapper : SymmetricCipherConfigurationWrapper
    {
        /// <summary>
        /// Name of the cryptographic block cipher transform being used e.g. AES, Blowfish, etc.
        /// </summary>
        public SymmetricBlockCiphers BlockCipher
        {
            get { return Config.CipherName.ToEnum<SymmetricBlockCiphers>(); }
            set { Config.CipherName = value.ToString(); }
        }

        /// <summary>
        /// Mode of operation of the block cipher being used, e.g. CBC, CTR, OFB, etc.
        /// </summary>
        public BlockCipherModes Mode
        {
            get { return Config.ModeName.ToEnum<BlockCipherModes>(); }
            set { Config.ModeName = value.ToString(); }
        }

        /// <summary>
        /// Scheme utillised to 'pad' blocks to full size where required. 
        /// What any unused space in a block is filled with. 
        /// Set to empty if using block cipher in streaming mode.
        /// </summary>
        public BlockCipherPaddings Padding
        {
            get { return Config.PaddingName.ToEnum<BlockCipherPaddings>(); }
            set { Config.PaddingName = value.ToString(); }
        }

        public int BlockSize
        {
            get { throw new NotImplementedException(); }
            set { throw new NotImplementedException(); }
        }

        public byte[] IV
        {
            get { throw new NotImplementedException(); }
            set { throw new NotImplementedException(); }
        }

        /// <summary>
        /// Outputs a summary of the configuration, optionally including the actual values of IV and Salt.
        /// </summary>
        /// <param name="includeValues">Whether to include values of relevant byte arrays as hex strings.</param>
        /// <returns></returns>
        public override string ToString(bool includeValues)
        {
            string cipher = Athena.Cryptography.BlockCipherDirectory[BlockCipher].DisplayName;
            string mode = Athena.Cryptography.BlockCipherModeDirectory[Mode].DisplayName;
            string padding = Padding == BlockCipherPaddings.None
                ? "None"
                : Athena.Cryptography.BlockCipherPaddingDirectory[Padding].DisplayName;
            if (includeValues)
            {
                string hexIV = IV.ToHexString();
                return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                    "Block size, bits: {3}\nMode: {4}\nPadding: {5}\n" +
                    "IV, hex: {6}",
                    SymmetricCipherType.Block, cipher, KeySize, BlockSize, mode, padding, hexIV);
            }
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                "Block size, bits: {3}\nMode: {4}\nPadding: {5}",
                SymmetricCipherType.Block, cipher, KeySize, BlockSize, mode, padding);
        }
    }


    public class AEADBlockCipherConfigurationWrapper : SymmetricCipherConfigurationWrapper
    {
        /// <summary>
        /// Name of the cryptographic block cipher transform being used e.g. AES, Blowfish, etc.
        /// </summary>
        public SymmetricBlockCiphers BlockCipher
        {
            get { return Config.CipherName.ToEnum<SymmetricBlockCiphers>(); }
            set { Config.CipherName = value.ToString(); }
        }

        /// <summary>
        /// Mode of the authenticated symmetric cipher mode being used, either GCM or CCM.
        /// </summary>
        public AEADBlockCipherModes Mode
        {
            get { return Config.ModeName.ToEnum<AEADBlockCipherModes>(); }
            set { Config.ModeName = value.ToString(); }
        }

        public int BlockSize
        {
            get { return Config.BlockSize; }
            set { Config.BlockSize = value; }
        }

        /// <summary>
        /// Number-used-once.
        /// </summary>
        public byte[] Nonce
        {
            get { return Config.IV; }
            set { Config.IV = value; }
        }

        public int MACSize
        {
            get { return Config.MACSize; }
            set { Config.MACSize = value; }
        }

        public byte[] AssociatedData
        {
            get { return Config.AssociatedData; }
            set { Config.AssociatedData = value; }
        }

        public override string ToString(bool includeValues)
        {
            string cipher = Athena.Cryptography.BlockCipherDirectory[BlockCipher].DisplayName;
            string mode = Athena.Cryptography.AEADBlockCipherModeDirectory[Mode].DisplayName;
            //string padding = Padding == BlockCipherPaddings.None ? 
            //"None" : Athena.Cryptography.BlockCipherPaddingDirectory[Padding].DisplayName;
            if (includeValues)
            {
                string hexNonce = (Nonce.Length == 0 ? "n/a" : Nonce.ToHexString());
                string hexAD = (Config.AssociatedData.Length == 0 ? "n/a" : Config.AssociatedData.ToHexString());
                return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                    "Block size, bits: {3}\nMode: {4}\nPadding: {5}\n" +
                    "MAC size: {6}\nNonce, hex: {7}\nAssociated data, hex: {8}",
                    SymmetricCipherType.AEAD, cipher, KeySize, Config.BlockSize, mode, "N/A",
                    Config.MACSize == 0 ? "n/a" : Config.MACSize.ToString(), hexNonce, hexAD);
            }
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                "Block size, bits: {3}\nMode: {4}\nPadding: {5}\nMAC size: {6}",
                SymmetricCipherType.AEAD, cipher, KeySize, Config.BlockSize, mode, "N/A",
                Config.MACSize == 0 ? "n/a" : Config.MACSize.ToString());
        }
    }


    public class StreamCipherConfigurationWrapper : SymmetricCipherConfigurationWrapper
    {
        /// <summary>
        /// Name of the cryptographic stream cipher transform being used e.g. Salsa20, VMPC, etc.
        /// </summary>
        public SymmetricStreamCiphers StreamCipherName
        {
            get { return Config.CipherName.ToEnum<SymmetricStreamCiphers>(); }
            set { Config.CipherName = value.ToString(); }
        }

        /// <summary>
        /// Number-used-once.
        /// </summary>
        public byte[] Nonce
        {
            get { return Config.IV; }
            set { Config.IV = value; }
        }

        public override string ToString(bool includeValues)
        {
            throw new NotImplementedException();
        }
    }
}
