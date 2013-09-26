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
using System.IO;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Modes;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Block.Primitives.Parameters;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.IO;
using ObscurCore.DTO;
using ObscurCore.Extensions.Enumerations;

namespace ObscurCore.Cryptography
{
	/// <summary>
	/// Decorating stream encapsulating and implementing encryption/decryption operations transparently.
	/// </summary>
	public sealed class SymmetricCryptoStream : DecoratingStream
	{
		/// <summary>
		/// What mode is active - encryption or decryption?
		/// </summary>
		public bool Encrypting { get; private set; }

		/// <summary>Initialises the stream and its associated cipher for operation automatically from provided configuration object.</summary>
		/// <param name="target">Stream to be written/read to/from.</param>
		/// <param name="isEncrypting">Specifies whether the stream is for writing (encrypting) or reading (decryption).</param>
		/// <param name="config">Configuration object describing how to set up the internal cipher and associated services.</param>
		/// <param name="key">Derived cryptographic key for the internal cipher to operate with.</param>
		/// <param name="leaveOpen">Set to <c>false</c> to also close the base stream when closing, or vice-versa.</param>
		public SymmetricCryptoStream (Stream target, bool isEncrypting, ISymmetricCipherConfiguration config, 
		                              bool leaveOpen = false) : base(isEncrypting, leaveOpen)
		{
			if (config.Key == null || config.Key.Length == 0) throw new ArgumentException("No key provided in field in config parameter object.");
            if(String.IsNullOrEmpty(config.CipherName)) throw new InvalidDataException("CipherName is null or empty.");

			Encrypting = isEncrypting;
			IBufferedCipher cipher;
			ICipherParameters cipherParams = null;

			// Determine if stream or block cipher
			if (Enum.GetNames(typeof(SymmetricBlockCiphers)).Contains(config.CipherName)) {
				// Requested a block or AEAD cipher.
                if(String.IsNullOrEmpty(config.ModeName)) throw new InvalidDataException("ModeName is null or empty (using block cipher).");

			    var blockCipherEnum = config.CipherName.ToEnum<SymmetricBlockCiphers>();

                if(!config.Key.Length.Equals(config.KeySize / 8))
                    throw new InvalidDataException("Specified key size does not match the supplied key.");

                if(!Athena.Cryptography.BlockCiphers[blockCipherEnum].AllowableBlockSizes.Contains(config.BlockSize)) 
                    throw new NotSupportedException("Specified block size is unsupported.");
                
                if(config.IV.Length != config.BlockSize / 8)
                    throw new NotSupportedException("IV length does not match block length.");
                
                BufferRequirementOverride = (config.BlockSize / 8) * 2;

				// Instantiate the cipher
				var blockCipher = Source.CreateBlockCipher(config.CipherName.ToEnum<SymmetricBlockCiphers>(), config.BlockSize);
				if (Enum.GetNames(typeof(BlockCipherModes)).Contains(config.ModeName)) {
					// Requested a block cipher.

                    cipherParams = Source.CreateBlockCipherParameters(config);

                    // Overlay the cipher with the mode of operation
                    blockCipher = Source.CreateBlockCipherWithMode(blockCipher, config.ModeName.ToEnum<BlockCipherModes>(),
				        config.BlockSize);

				    // Create the I/O-enabled transform object
					if (!config.PaddingName.Equals(BlockCipherPaddings.None.ToString()) && !String.IsNullOrEmpty(config.PaddingName)) {
						var padding = Source.CreatePadding(config.PaddingName.ToEnum<BlockCipherPaddings>());
						cipher = new PaddedBufferedBlockCipher(blockCipher, padding);
					} else if (config.ModeName.Equals(BlockCipherModes.CTS_CBC.ToString())) {
						cipher = new CtsBlockCipher(blockCipher);
					} else {
						// No padding specified - is this OK in the context of the mode of operation?
						if(Athena.Cryptography.BlockModes[config.ModeName.ToEnum<BlockCipherModes>()].PaddingRequirement
                            == PaddingRequirements.Always) {
							throw new NotSupportedException("Cipher configuration does not specify the use of padding, " + 
                                "which is required for the specified mode of operation.");
						}
						cipher = new BufferedBlockCipher(blockCipher);
					}

				} else if (Enum.GetNames(typeof(AEADBlockCipherModes)).Contains(config.ModeName)) {
					// Requested an AEAD cipher (block cipher inside).

                    if(config.MACSize / 8 != config.IV.Length)
                    throw new NotSupportedException("Nonce size does not match MAC size.");

				    cipherParams = Source.CreateAEADBlockCipherParameters(config);

					// Overlay the cipher with the mode of operation
					var aeadCipher = Source.CreateBlockCipherWithAEAD(config.ModeName.ToEnum<AEADBlockCipherModes>() , blockCipher);

					// Create the I/O-enabled transform object
					if (!config.PaddingName.Equals(BlockCipherPaddings.None.ToString()) && !config.PaddingName.Equals(""))
						throw new NotSupportedException("Padding specified for use with AEAD mode (not allowed/unnecessary).");
					cipher = new BufferedAeadBlockCipher(aeadCipher);
				} else {
					throw new ArgumentException("Unsupported/unknown block cipher mode.");
				}

			} else if (Enum.GetNames(typeof(SymmetricStreamCiphers)).Contains(config.CipherName)) {
				// Requested a stream cipher.
#if(INCLUDE_RC4)
                cipherParams = Source.CreateKeyParameter(config.Key);
#else
                cipherParams = Source.CreateStreamCipherParameters(config.Key, config.IV);
#endif
				// Instantiate the cipher
				var streamCipher = Source.CreateStreamCipher(config.CipherName.ToEnum<SymmetricStreamCiphers>());
				// Create the I/O-enabled transform object
				cipher = new BufferedStreamCipher(streamCipher);
			} else {
				throw new ArgumentException("Unsupported/unknown cipher.");
			}

			// Initialise the cipher
			cipher.Init(isEncrypting, cipherParams);
			BoundStream = new ExtendedCipherStream(target, isEncrypting, cipher, leaveOpen);
		}

		/// <summary>
		/// Closing the stream will cause the internal cipher to perform transformation of the final block automagically. Best practice is use of a 'using' block. 
		/// Closure may also cause the base stream to close - this depends on the provided value of the constructor parameter 'leaveOpen'.
		/// </summary>
		/// <exception cref="PaddingException">Thrown when no padding, malformed padding, or misaligned padding is found.</exception>
		/// <exception cref="IncompleteBlockException">Thrown when ciphertext is not a multiple of block size (unexpected length).</exception>
		public override void Close() {
			var cipher = Encrypting ? ((ExtendedCipherStream) BoundStream).outCipher : ((ExtendedCipherStream) BoundStream).inCipher;
			// Catch all possible errors. Many unique types, caused by authentication failures, padding corruption, general corruption, etc.
			try {
				// Cause final transformation to take place if block/AEAD cipher, and then closing the stream.
				BoundStream.Close();
			} catch (DataLengthException dlEx) {
				if (cipher is IAeadBlockCipher) {
					// No example here, but leaving it here anyway for possible future implemention.
				} else if (cipher is PaddedBufferedBlockCipher) {
					switch (dlEx.Message) {
						case "last block incomplete in decryption":
						throw new PaddingException("The data in the ciphertext is not the expected length.");
						case "output buffer too short":
						throw new EndOfStreamException("Could not write transformed block bytes to output stream."); // TODO: change this ex type
						default:
						throw new PaddingException("The ciphertext padding is corrupt.");
					}
				} else if (cipher is BufferedBlockCipher) {
					switch (dlEx.Message) {
						case "data not block size aligned":
						throw new IncompleteBlockException("The data in the ciphertext is not the expected length.");
						case "output buffer too short":
						case "output buffer too short for DoFinal()":
						throw new EndOfStreamException("Could not write transformed block bytes to output stream."); // TODO: change this ex type
						default:
						throw new DataLengthException("An unknown type of error occured while transforming the final block of ciphertext.", dlEx);
					}
				} else {
					// No example here, but leaving it here anyway for possible future implementation.
				}
			} catch (InvalidCipherTextException ctEx) {
				if (cipher is IAeadBlockCipher) {
					switch (ctEx.Message) { // Heuristically unreachable - verify the operation of this section.
						case "data too short":
						throw new IncompleteBlockException();
						case "mac check in GCM failed":
						case "mac check in EAX failed":
						throw new AuthenticationException("The calculated MAC for the ciphertext is different to the supplied MAC.");
					}
				} else if(cipher is PaddedBufferedBlockCipher) {
					switch (ctEx.Message) {
						case "pad block corrupted":
						throw new PaddingException();
						default:
						throw new InvalidCipherTextException("An unknown type of error occured while transforming the final block of ciphertext.", ctEx);
					}
				} else if (cipher is BufferedBlockCipher) {
					throw new InvalidCipherTextException("An unknown type of error occured while transforming the final block of ciphertext.", ctEx);
				} else {
					// No example here, but leaving it here anyway for possible future implementation.
				}
			}
		}

		/// <summary>
		/// This does NOT cause the last block to be transformed. The stream must be closed for this to happen. Not recommended for use!
		/// </summary>
		public override void Flush() {
			BoundStream.Flush();
		}

		#region Derived ExtendedCipherStream for leave-open
		/// <summary>
		/// Internal ObscurCore component for adding leave-open functionality to the base CipherStream, essential to the functioning of the Core pipeline.
		/// </summary>
		private sealed class ExtendedCipherStream : CipherStream
		{
			private readonly bool _leaveOpen;
			private readonly bool _encrypting;

            public ExtendedCipherStream (Stream stream, bool encrypting, IBufferedCipher cipher, bool leaveOpen)
				: base(stream, encrypting ? null : cipher, encrypting ? cipher : null) {
				_leaveOpen = leaveOpen;
				_encrypting = encrypting;
			}

			public override bool CanRead {
				get { return stream.CanRead && inCipher != null; }
			}

			public override bool CanWrite {
				get { return stream.CanWrite && outCipher != null; }
			}

			public override void Close () {
                if (_encrypting) {
                    var data = outCipher.DoFinal();
				    stream.Write(data, 0, data.Length);
				    try {
					    stream.Flush ();
				    } catch (Exception e) {
					    throw new IOException("Error on flushing internal bound stream.", e);
				    }
                }
				if (!_leaveOpen) stream.Close();
			}
		}
		#endregion
	}
}
