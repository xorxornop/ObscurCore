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
using ObscurCore.Extensions.Enumerations;
using ProtoBuf;

namespace ObscurCore.Cryptography
{
	public static class SymmetricCipherConfigurationFactory
	{
		/*public static BlockCipherConfiguration CreateBlockCipherConfiguration(SymmetricBlockCiphers cipher,
			BlockCipherModes mode, BlockCipherPaddingTypes? padding, int? blockSize = null, int? keySize = null) {
			
		}*/
	}
	
	/// <summary>
	/// Configuration for a block cipher.
	/// </summary>
	public class BlockCipherConfiguration : SymmetricCipherConfiguration
	{
		public BlockCipherConfiguration(SymmetricBlockCiphers cipher, BlockCipherModes mode, BlockCipherPaddings padding, 
		                                int? blockSize = null, int? keySize = null) {
			// Set the block size
			var blockSizeNonNull = blockSize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultBlockSize;
			if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableBlockSizes.Contains(blockSizeNonNull))
				BlockSize = blockSizeNonNull;
			else throw new BlockSizeException(blockSizeNonNull, Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName + " specification");
			// Set the key size
			var keySizeNonNull = keySize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultKeySize;
			if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableKeySizes.Contains(keySizeNonNull))
				KeySize = keySizeNonNull;
			else throw new KeySizeException(keySizeNonNull, Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName + " specification");
			// Set the mode
			if (Athena.Cryptography.BlockCipherModeDirectory[mode].PaddingRequirement == PaddingRequirements.Always && padding == BlockCipherPaddings.None) { // TODO: Refine my logic!
				throw new ArgumentException(mode + " mode must be used with padding or errors will occur when plaintext length is not equal to or a multiple of the block size.");
			}
			Mode = mode;
			Padding = padding;
			BlockCipher = cipher;

            // TODO: Review this code, make more resource efficient.
            IV = new byte[BlockSize / 8];
		    StratCom.EntropySource.NextBytes(IV);
		}
		
		/// <summary>
		/// Name of the cryptographic block cipher transform being used e.g. AES, Blowfish, etc.
		/// </summary>
		public SymmetricBlockCiphers BlockCipher
		{
            get {
                SymmetricBlockCiphers outEnum;
                CipherName.ToEnum(out outEnum);
                return outEnum;
            }
            set { CipherName = value.ToString(); }
		}
		
		/// <summary>
		/// Mode of operation of the block cipher being used, e.g. CBC, CTR, OFB, etc.
		/// </summary>
		public BlockCipherModes Mode
		{
            get {
                BlockCipherModes outEnum;
                ModeName.ToEnum(out outEnum);
                return outEnum;
            }
            set { ModeName = value.ToString(); }
		}
		
		/// <summary>
		/// Scheme utillised to 'pad' blocks to full size where required. 
		/// What any unused space in a block is filled with. 
		/// Set to empty if using block cipher in streaming mode.
		/// </summary>
		public BlockCipherPaddings Padding
		{
            get {
                BlockCipherPaddings outEnum;
                PaddingName.ToEnum(out outEnum);
                return outEnum;
            }
            set { PaddingName = value.ToString(); }
		}
		
		/// <summary>
		/// Outputs a summary of the configuration, optionally including the actual values of IV and Salt.
		/// </summary>
		/// <param name="includeValues">Whether to include values of relevant byte arrays as hex strings.</param>
		/// <returns></returns>
		public override string ToString (bool includeValues) {
			string cipher = Athena.Cryptography.BlockCipherDirectory[CipherName.ToEnum<SymmetricBlockCiphers>()].DisplayName;
			string mode = Athena.Cryptography.BlockCipherModeDirectory[Mode].DisplayName;
            string padding = Padding == BlockCipherPaddings.None ?
                "None" : Athena.Cryptography.BlockCipherPaddingDirectory[Padding].DisplayName;
			if (includeValues) {
				string hexIV = ByteArrayToHexString(IV);
				return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" + 
				                     "Block size, bits: {3}\nMode: {4}\nPadding: {5}\n" +
				                     "IV, hex: {6}",
				                     Type.ToString(), cipher, KeySize, BlockSize, mode, padding, hexIV);
			}
			return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" + 
			                     "Block size, bits: {3}\nMode: {4}\nPadding: {5}",
			                     Type.ToString(), cipher, KeySize, BlockSize, mode, padding);
		}
	}


    /// <summary>
    /// Configuration for a Authenticated Encryption/Decryption (AEAD) cipher.
    /// </summary>
    public class AEADCipherConfiguration : SymmetricCipherConfiguration
    {
        /// <summary>Use this constructor for configuring an AEAD (Authenticated Encryption/decryption with Associated Data) cipher.</summary>
        /// <param name="cipher">Enumeration of the cipher algorithm to use.</param>
        /// <param name="mode">Enumeration of the block cipher mode to use.</param>
        /// <param name="padding">Type of padding to use to increase length of data to a multiple of the block size, where required.
        /// Generally unecessary for AEAD operation.</param>
        /// <param name="keySize">Size of the key to use in the cipher, in bits. Set to null to use default for the cipher.</param>
        /// <param name="blockSize">The block size to use in the cipher, in bits. Set to null to use default for the cipher.</param>
        /// <param name="macSize">Size of the MAC to use in the AEAD cipher, in bits. Set to null to use default for the cipher.</param>
        public AEADCipherConfiguration(SymmetricBlockCiphers cipher, AEADBlockCipherModes mode,
                                       BlockCipherPaddings padding = BlockCipherPaddings.None,
                                       int? keySize = null, int? blockSize = null, int? macSize = null) {
            // Set the block size
            var blockSizeNonNull = blockSize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultBlockSize;
            // TODO: Add in a section to handle MAC and block sizes seperately.
            if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableBlockSizes.Contains(blockSizeNonNull)) BlockSize = blockSizeNonNull;
            else
                throw new BlockSizeException(blockSizeNonNull,
                                           Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName +
                                           " specification");
            // Set the key size
            int keySizeNonNull = keySize ?? Athena.Cryptography.BlockCipherDirectory[cipher].DefaultKeySize;
            if (Athena.Cryptography.BlockCipherDirectory[cipher].AllowableKeySizes.Contains(keySizeNonNull)) KeySize = keySizeNonNull;
            else
                throw new KeySizeException(keySizeNonNull,
                                           Athena.Cryptography.BlockCipherDirectory[cipher].DisplayName +
                                           " specification");
            // Set the mode
            if (Athena.Cryptography.AEADBlockCipherModeDirectory[mode].PaddingRequirement == PaddingRequirements.Always && padding == BlockCipherPaddings.None) // TODO: Refine my logic!
            {
                throw new ArgumentException(mode +
                                            " mode must be used with padding or errors will occur when plaintext length is not equal to or a multiple of the block size.");
            }
            // Check if the AEAD mode supports the block size
            int macSizeNonNull = macSize ?? BlockSize;
            if (!Athena.Cryptography.AEADBlockCipherModeDirectory[mode].AllowableBlockSizes.Contains(-1)) {
                if (Athena.Cryptography.AEADBlockCipherModeDirectory[mode].AllowableBlockSizes.Contains(BlockSize)) MACSize = macSizeNonNull;
                    else throw new MACSizeException(macSizeNonNull, Athena.Cryptography.AEADBlockCipherModeDirectory[mode].DisplayName +
                                            " specification");
            }

            Mode = mode;
            Padding = padding;
            BlockCipher = cipher;
            // TODO: Review this code, make more resource efficient.
            IV = new byte[BlockSize / 8]; // Nonce in AEAD
            StratCom.EntropySource.NextBytes(IV);
        }

        /// <summary>
        /// Name of the cryptographic block cipher transform being used e.g. AES, Blowfish, etc.
        /// </summary>
        public SymmetricBlockCiphers BlockCipher
        {
            get {
                SymmetricBlockCiphers outEnum;
                CipherName.ToEnum(out outEnum);
                return outEnum;
            }
            set { CipherName = value.ToString(); }
        }

        /// <summary>
        /// Mode of the authenticated symmetric cipher mode being used, either GCM or CCM.
        /// </summary>
        public AEADBlockCipherModes Mode
        {
            get {
                AEADBlockCipherModes outEnum;
                ModeName.ToEnum(out outEnum);
                return outEnum;
            }
            set { ModeName = value.ToString(); }
        }

        /// <summary>
        /// Scheme utillised to 'pad' blocks to full size where required. 
        /// What any unused space in a block is filled with. 
        /// Set to empty if using block cipher in streaming mode.
        /// </summary>
        public BlockCipherPaddings Padding
        {
            get {
                BlockCipherPaddings outEnum;
                PaddingName.ToEnum(out outEnum);
                return outEnum;
            }
            set { PaddingName = value.ToString(); }
        }

        /// <summary>
        /// Number-used-once.
        /// </summary>
        public byte[] Nonce {
            get { return IV; }
            set { IV = value; }
        }

		/// <summary>
		/// Outputs a summary of the configuration, optionally including the actual values of Nonce/Salt/AD.
		/// </summary>
		/// <param name="includeValues">Whether to include values of relevant byte arrays as hex strings.</param>
		/// <returns></returns>
		public override string ToString (bool includeValues) {
			string cipher = Athena.Cryptography.BlockCipherDirectory[BlockCipher].DisplayName;
			string mode = Athena.Cryptography.AEADBlockCipherModeDirectory[Mode].DisplayName;
			string padding = Padding == BlockCipherPaddings.None ? 
                "None" : Athena.Cryptography.BlockCipherPaddingDirectory[Padding].DisplayName;
			if (includeValues) {
				string hexNonce = (Nonce.Length == 0 ? "n/a" : ByteArrayToHexString(Nonce));
				string hexAD = (AssociatedData.Length == 0 ? "n/a" : ByteArrayToHexString(AssociatedData));
				return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" + 
				                     "Block size, bits: {3}\nMode: {4}\nPadding: {5}\n" +
				                     "MAC size: {6}\nNonce, hex: {7}\nAssociated data, hex: {8}",
				                     Type.ToString(), cipher, KeySize, BlockSize, mode, padding,
				                     MACSize == 0 ? "n/a" : MACSize.ToString(), hexNonce, hexAD);
			}
			return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}\n" + 
			                     "Block size, bits: {3}\nMode: {4}\nPadding: {5}\nMAC size: {6}",
			                     Type.ToString(), cipher, KeySize, BlockSize, mode, padding,
			                     MACSize == 0 ? "n/a" : MACSize.ToString());
		}
	}
	
	/// <summary>
	/// Configuration for a stream cipher.
	/// </summary>
	public class StreamCipherConfiguration : SymmetricCipherConfiguration
	{		
		/// <summary>Use this constructor for configuring a stream cipher.</summary>
		/// <param name="cipher">Enumeration of the cipher algorithm to use.</param>
		/// <param name="keySize">Size of the key used in the cipher, in bits. Set to null to use default for the cipher.</param>
		public StreamCipherConfiguration(SymmetricStreamCiphers cipher, int? keySize = null) {
			int keySizeNonNull = keySize ?? Athena.Cryptography.StreamCipherDirectory[cipher].DefaultKeySize;
			if (Athena.Cryptography.StreamCipherDirectory[cipher].AllowableKeySizes.Contains(keySizeNonNull)) KeySize = keySizeNonNull;
			else throw new KeySizeException(keySizeNonNull, Athena.Cryptography.StreamCipherDirectory[cipher].DisplayName + " specification");
			StreamCipherName = cipher;
            // TODO: Review this code, make more resource efficient.
			IV = new byte[Athena.Cryptography.StreamCipherDirectory[cipher].DefaultIVSize / 8];

            StratCom.EntropySource.NextBytes(IV);
		}
		
		
		/// <summary>
		/// Name of the cryptographic stream cipher transform being used e.g. Salsa20, VMPC, etc.
		/// </summary>
		public SymmetricStreamCiphers StreamCipherName
		{
            get {
                SymmetricStreamCiphers outEnum;
                CipherName.ToEnum(out outEnum);
                return outEnum;
            }
            set { CipherName = value.ToString(); }
		}
	}

    public class KeySizeException : Exception
    {
        public KeySizeException (int size, string restriction)
            : base(String.Format("The key size {0} is not supported in the {1}.", size, restriction)) {
            SelectedSize = size;
            CipherRestriction = restriction;
        }
        public int SelectedSize { get; private set; }
        public string CipherRestriction { get; private set; }
    }

    public class BlockSizeException : Exception
    {
        public BlockSizeException (int size, string restriction)
            : base(String.Format("The block size {0} is not supported in the {1}.", size, restriction)) {
            SelectedSize = size;
            CipherRestriction = restriction;
        }
        public int SelectedSize { get; private set; }
        public string CipherRestriction { get; private set; }
    }

    public class MACSizeException : Exception
    {
        public MACSizeException (int size, string restriction)
            : base(String.Format("The MAC size {0} is not supported in the {1}.", size, restriction)) {
            SelectedSize = size;
            CipherRestriction = restriction;
        }
        public int SelectedSize { get; private set; }
        public string CipherRestriction { get; private set; }
    }
}
