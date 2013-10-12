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
using ObscurCore.Cryptography.Ciphers.Stream;
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
		                              byte[] key = null, bool leaveOpen = false) : base(isEncrypting, leaveOpen)
		{
            if ((config.Key == null || config.Key.Length == 0) && (key == null || key.Length == 0)) 
                throw new ArgumentException("No key provided in field in configuration object or as parameter.");

            Encrypting = isEncrypting;
			IBufferedCipher cipher;
			ICipherParameters cipherParams = null;

            byte[] workingKey = config.Key ?? key;

		    switch (config.Type) {
                case SymmetricCipherType.None:
		            throw new ConfigurationException("Type: None/null value is never set in a valid cipher configuration.");
		        case SymmetricCipherType.Block:
                case SymmetricCipherType.AEAD:

                    var blockCipherEnum = SymmetricBlockCiphers.None;
		            try {
		                blockCipherEnum = config.CipherName.ToEnum<SymmetricBlockCiphers>();
		            } catch (EnumerationValueUnknownException e) {
		                throw new ConfigurationException(e);
		            }

                    if(!workingKey.Length.Equals(config.KeySize / 8))
                        throw new InvalidDataException("Key is not of the declared length.");
                    if(!Athena.Cryptography.BlockCipherDirectory[blockCipherEnum].AllowableBlockSizes.Contains(config.BlockSize)) 
                        throw new NotSupportedException("Specified block size is unsupported.");

                    BufferRequirementOverride = (config.BlockSize / 8) * 2;

                    var blockCipher = Source.CreateBlockCipher(blockCipherEnum, config.BlockSize);

		            switch (config.Type) {
                        case SymmetricCipherType.Block:

		                    var blockModeEnum = BlockCipherModes.None;
		                    try {
		                        blockModeEnum = config.ModeName.ToEnum<BlockCipherModes>();
		                    } catch (EnumerationValueUnknownException e) {
		                        throw new ConfigurationException(e);
		                    }

                            if(config.IV.Length != config.BlockSize / 8)
                                throw new NotSupportedException("IV length does not match block length.");

                            cipherParams = Source.CreateBlockCipherParameters(config);
                            // Overlay the cipher with the mode of operation
                            blockCipher = Source.CreateBlockCipherWithMode(blockCipher, blockModeEnum,
				                config.BlockSize);

                            var paddingEnum = BlockCipherPaddings.None;
		                    try {
		                        paddingEnum = config.PaddingName.ToEnum<BlockCipherPaddings>();
		                    } catch (EnumerationValueUnknownException e) {
		                        throw new ConfigurationException(e);
		                    }

		                    if (blockModeEnum == BlockCipherModes.CTS_CBC) {
		                        if (paddingEnum == BlockCipherPaddings.None) {
                                    cipher = new CtsBlockCipher(blockCipher);
                                } else {
                                    throw new ConfigurationException("CTS mode is inappropriate for use with padding.");
                                }
		                    } else if (paddingEnum == BlockCipherPaddings.None) {
		                        if (Athena.Cryptography.BlockCipherModeDirectory[
		                            config.ModeName.ToEnum<BlockCipherModes>()]
		                            .PaddingRequirement == PaddingRequirements.Always) {
		                            throw new NotSupportedException(
		                                "Cipher configuration does not specify the use of padding, " +
		                                    "which is required for the specified mode of operation.");
		                        }
		                        cipher = new BufferedBlockCipher(blockCipher);
		                    } else {
		                        var padding = Source.CreatePadding(paddingEnum);
		                        cipher = new PaddedBufferedBlockCipher(blockCipher, padding);
		                    }

		                    break;
		                case SymmetricCipherType.AEAD:

                            var aeadModeEnum = AEADBlockCipherModes.None;
		                    try {
		                        aeadModeEnum = config.ModeName.ToEnum<AEADBlockCipherModes>();
		                    } catch (EnumerationValueUnknownException e) {
		                        throw new ConfigurationException(e);
		                    }

                            cipherParams = Source.CreateAEADBlockCipherParameters(blockCipherEnum,
				                workingKey, config.IV, config.MACSize, config.AssociatedData);
                            // Overlay the cipher with the mode of operation
					        var aeadCipher = Source.CreateBlockCipherWithAEAD(aeadModeEnum, blockCipher);

					        // Create the I/O-enabled transform object
					        if (!config.PaddingName.Equals(BlockCipherPaddings.None.ToString()) && !config.PaddingName.Equals(""))
						        throw new NotSupportedException("Padding specified for use with AEAD mode (not allowed/unnecessary).");
					        cipher = new BufferedAeadBlockCipher(aeadCipher);

		                    break;
		                default:
		                    throw new ArgumentOutOfRangeException();
		            }
		            break;
		        case SymmetricCipherType.Stream:

                    BufferRequirementOverride = config.IV != null && config.IV.Length > 0 ? (config.IV.Length) * 2 : (config.KeySize / 8) * 2;

                    var streamCipherEnum = SymmetricStreamCiphers.None;
		            try {
		                streamCipherEnum = config.CipherName.ToEnum<SymmetricStreamCiphers>();
		            } catch (EnumerationValueUnknownException e) {
		                throw new ConfigurationException(e);
		            }

				    // Requested a stream cipher.
                    cipherParams = Source.CreateStreamCipherParameters(streamCipherEnum, workingKey, config.IV);
				    // Instantiate the cipher
				    var streamCipher = Source.CreateStreamCipher(streamCipherEnum);
				    // Create the I/O-enabled transform object
				    cipher = new BufferedStreamCipher(streamCipher);

		            break;
		        default:
		            throw new ArgumentOutOfRangeException();
		    }

			// Initialise the cipher
			cipher.Init(isEncrypting, cipherParams);
			BoundStream = new ExtendedCipherStream(target, isEncrypting, cipher, leaveOpen);
		}

		/// <summary>
		/// Closing the stream will cause the internal cipher to perform transformation of the final block automagically. Best practice is use of a 'using' block. 
		/// Closure may also cause the base stream to close.
		/// </summary>
		/// <exception cref="PaddingException">Thrown when no padding, malformed padding, or misaligned padding is found.</exception>
		/// <exception cref="IncompleteBlockException">Thrown when ciphertext is not a multiple of block size (unexpected length).</exception>
		/// <exception cref="DataLengthException">Thrown when final bytes could not be written to the output.</exception>
		/// <exception cref="AuthenticationException">Thrown when MAC/authentication check fails to match with expected value. AEAD-relevant.</exception>
		public override void Close() {
		    const string unknownEx = "An unknown type of error occured while transforming the final block of ciphertext.";
		    const string unexpectedLength = "The data in the ciphertext is not the expected length.";
		    const string writingError = "Could not write transformed block bytes to output stream.";
            
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
						throw new PaddingException(unexpectedLength);
						case "output buffer too short":
						throw new DataLengthException(writingError);
						default:
						throw new PaddingException("The ciphertext padding is corrupt.");
					}
				} else if (cipher is BufferedBlockCipher) {
					switch (dlEx.Message) {
						case "data not block size aligned":
						throw new IncompleteBlockException(unexpectedLength);
						case "output buffer too short":
						case "output buffer too short for DoFinal()":
						throw new DataLengthException(writingError);
						default:
						throw new DataLengthException(unknownEx, dlEx);
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
						throw new InvalidCipherTextException(unknownEx, ctEx);
					}
				} else if (cipher is BufferedBlockCipher) {
					throw new InvalidCipherTextException(unknownEx, ctEx);
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
