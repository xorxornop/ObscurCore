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

namespace ObscurCore.Cryptography
{
    public class AeadBlockCipherConfigurationWrapper : SymmetricCipherConfigurationWrapper
    {
        public AeadBlockCipherConfigurationWrapper(SymmetricCipherConfiguration config) : base(config) {}

        protected override void ThrowIfKeySizeIncompatible() {
            if (!Athena.Cryptography.BlockCiphers[BlockCipher].AllowableKeySizes.Contains(RawConfiguration.KeySizeBits)) {
                throw new KeySizeException(BlockCipher, RawConfiguration.KeySizeBits);
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
                    throw new ConfigurationException("Cipher unknown/unsupported.", e);
                }
                return blockCipherEnum;
            }
            set { RawConfiguration.CipherName = value.ToString(); }
        }

        /// <summary>
        /// Mode of the authenticated symmetric cipher mode being used, either GCM or CCM.
        /// </summary>
        public AeadBlockCipherMode Mode
        {
            get { return RawConfiguration.ModeName.ToEnum<AeadBlockCipherMode>(); }
            set { RawConfiguration.ModeName = value.ToString(); }
        }

        public int BlockSize
        {
            get {
                if (Configuration.BlockSizeBits == 0) {
                    throw new ConfigurationException("Block cipher cannot have a block size of 0 (zero).");
                }
                ThrowIfBlockSizeIncompatible();
                return RawConfiguration.BlockSizeBits;
            }
            set { RawConfiguration.BlockSizeBits = value; }
        }

        protected void ThrowIfBlockSizeIncompatible() {
            if (!Athena.Cryptography.BlockCiphers[BlockCipher].AllowableBlockSizes.Contains(Configuration.BlockSizeBits)) {
                throw new BlockSizeException(BlockCipher, Configuration.BlockSizeBits);
            }
        }

        /// <summary>
        /// Number-used-once. Similar to the IV for a block cipher.
        /// </summary>
        public byte[] Nonce
        {
            get {
                if (Configuration.IV.IsNullOrZeroLength()) {
                    throw new ConfigurationException("AEAD cipher cannot have a nonce (IV) of null or zero length.");
                }
                var retVal = new byte[RawConfiguration.IV.Length];
                Buffer.BlockCopy(RawConfiguration.IV, 0, retVal, 0, RawConfiguration.IV.Length);
                return retVal;
            }
            set { RawConfiguration.IV = value; }
        }

        public int MacSize
        {
            get { return RawConfiguration.MacSizeBits; }
            set { RawConfiguration.MacSizeBits = value; }
        }

        public byte[] AssociatedData
        {
            get {
                var retVal = new byte[RawConfiguration.AssociatedData.Length];
                Buffer.BlockCopy(RawConfiguration.AssociatedData, 0, retVal, 0, RawConfiguration.AssociatedData.Length);
                return retVal;
            }
            set { RawConfiguration.AssociatedData = value; }
        }

        public override string ToString(bool includeValues)
        {
            var cipher = Athena.Cryptography.BlockCiphers[BlockCipher].DisplayName;
            var mode = Athena.Cryptography.AeadBlockCipherModes[Mode].DisplayName;
            //string padding = Padding == BlockCipherPaddings.None ? 
            //"None" : Athena.Cryptography.BlockCipherPaddingDirectory[Padding].DisplayName;
            if (includeValues)
            {
                var hexNonce = (Nonce.IsNullOrZeroLength() ? "n/a" : Nonce.ToHexString());
                var hexAD = (RawConfiguration.AssociatedData.IsNullOrZeroLength() ? "n/a" : RawConfiguration.AssociatedData.ToHexString());
                return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                    "Block size, bits: {3}\nMode: {4}\n" +
                    "MAC size: {5}\nNonce, hex: {6}\nAssociated data, hex: {7}",
                    SymmetricCipherType.Aead, cipher, KeySizeBits, RawConfiguration.BlockSizeBits, mode,
                    RawConfiguration.MacSizeBits == 0 ? "n/a" : RawConfiguration.MacSizeBits.ToString(), hexNonce, hexAD);
            }
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" +
                "Block size, bits: {3}\nMode: {4}\nMAC size: {5}",
                SymmetricCipherType.Aead, cipher, KeySizeBits, RawConfiguration.BlockSizeBits, mode,
                RawConfiguration.MacSizeBits == 0 ? "n/a" : RawConfiguration.MacSizeBits.ToString());
        }
    }
}