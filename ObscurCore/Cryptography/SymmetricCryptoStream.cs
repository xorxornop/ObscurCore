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
using System.Diagnostics;
using System.Linq;
using System.IO;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Modes;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;

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
		public bool Encrypting {
			get { return base.Writing; }
		}

		private IBufferedCipher _cipher;
		private readonly RingByteBuffer _procBuffer;
		private readonly byte[] _inBuffer;
		private byte[] _outBuffer; // non-readonly allows for on-the-fly reassignment for CTS compat. during finalisation.
		private bool _inStreamEnded;
		private bool _disposed;

		private const int StreamStride = 64;
		private const int ProcessingIOStride = 4096;

		private const string UnknownFinaliseError = "An unknown type of error occured while transforming the final block of ciphertext.";
		private const string UnexpectedLengthError = "The data in the ciphertext is not the expected length.";
		private const string WritingError = "Could not write transformed block bytes to output stream.";
		private const string ShortCTSError = "Insufficient input length. CTS mode block ciphers require at least one block.";

		/// <summary>Initialises the stream and its associated cipher for operation automatically from provided configuration object.</summary>
		/// <param name="target">Stream to be written/read to/from.</param>
		/// <param name="isEncrypting">Specifies whether the stream is for writing (encrypting) or reading (decryption).</param>
		/// <param name="config">Configuration object describing how to set up the internal cipher and associated services.</param>
		/// <param name="key">Derived cryptographic key for the internal cipher to operate with. Overrides key in configuration.</param>
		/// <param name="leaveOpen">Set to <c>false</c> to also close the base stream when closing, or vice-versa.</param>
		public SymmetricCryptoStream (Stream target, bool isEncrypting, ISymmetricCipherConfiguration config, 
		                              byte[] key = null, bool leaveOpen = false) : base(target, isEncrypting, !leaveOpen, true)
		{
            if ((config.Key == null || config.Key.Length == 0) && (key == null || key.Length == 0)) 
                throw new ArgumentException("No key provided in field in configuration object or as parameter.");

			ICipherParameters cipherParams = null;

            byte[] workingKey = key ?? config.Key;

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

                    base.BufferRequirementOverride = (config.BlockSize / 8) * 2;

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
                            blockCipher = Source.OverlayBlockCipherWithMode(blockCipher, blockModeEnum,
				                config.BlockSize);

                            var paddingEnum = BlockCipherPaddings.None;
		                    try {
		                        paddingEnum = config.PaddingName.ToEnum<BlockCipherPaddings>();
		                    } catch (EnumerationValueUnknownException e) {
		                        throw new ConfigurationException(e);
		                    }

		                    if (blockModeEnum == BlockCipherModes.CTS_CBC) {
		                        if (paddingEnum == BlockCipherPaddings.None) {
                                    _cipher = new CtsBlockCipher(blockCipher);
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
		                        _cipher = new BufferedBlockCipher(blockCipher);
		                    } else {
		                        var padding = Source.CreatePadding(paddingEnum);
		                        _cipher = new PaddedBufferedBlockCipher(blockCipher, padding);
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
					        var aeadCipher = Source.OverlayBlockCipherWithAEADMode(blockCipher, aeadModeEnum);

					        // Create the I/O-enabled transform object
					        if (!config.PaddingName.Equals(BlockCipherPaddings.None.ToString()) && !config.PaddingName.Equals(""))
						        throw new NotSupportedException("Padding specified for use with AEAD mode (not allowed/unnecessary).");
					        _cipher = new BufferedAeadBlockCipher(aeadCipher);

		                    break;
		            }
		            break;
		        case SymmetricCipherType.Stream:

                    base.BufferRequirementOverride = config.IV != null && config.IV.Length > 0 ? (config.IV.Length) * 2 : (config.KeySize / 8) * 2;

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
				    _cipher = new BufferedStreamCipher(streamCipher);

		            break;
		        default:
		            throw new ArgumentOutOfRangeException();
		    }

			// Initialise the cipher
			_cipher.Init(isEncrypting, cipherParams);
			// Initialise the buffers
			var opSize = _cipher.GetBlockSize(); 
			if (opSize == 0)
				opSize = StreamStride;
			else if (_cipher is CtsBlockCipher)
				opSize *= 2;
			_inBuffer = new byte[opSize];
			_outBuffer = new byte[opSize];
			_procBuffer = new RingByteBuffer (opSize << 8);
			// Shift left 8 upscales : 8 (64 bits) to 2048 [2kB], 16 (128) to 4096 [4kB], 32 (256) to 8192 [8kB]

			// Customise the decorator-stream exception messages, since we enforce processing direction in this implementation
			NotEffluxError = "Stream is configured for encryption, and so may only be written to.";
			NotInfluxError = "Stream is configured for decryption, and so may only be read from.";
		}

		public override bool CanSeek {
			get { return false; }
		}

		public override long Seek (long offset, SeekOrigin origin) {
			throw new NotSupportedException ();
		}

		public override void Write (byte[] buffer, int offset, int count) {
			CheckIfAllowed (true);

			while (count > 0) {
				// Process and put the resulting bytes in procbuffer
				var opSize = Math.Min (count, _outBuffer.Length);
				var processed = _cipher.ProcessBytes(buffer, offset, opSize, _outBuffer, 0);
				BytesIn += opSize;
				_procBuffer.Put (_outBuffer, 0, processed);
				offset += opSize;
				count -= opSize;

				// Prevent procbuffer overflow where applicable
				if(_procBuffer.Spare < count) {
					var overflowOut = _procBuffer.Length;
					// Write out the processed bytes to stream
					_procBuffer.TakeTo (Binding, overflowOut);
					BytesOut += overflowOut;
				}
			}

			// Write out the processed bytes to stream
			var writeOut = _procBuffer.Length;
			_procBuffer.TakeTo (Binding, writeOut);
			BytesOut += writeOut;
		}

		public override void WriteByte (byte b) {
			CheckIfAllowed (true);

			if(_procBuffer.Length == 0) {
				var bytes = _cipher.ProcessByte (b);
				_procBuffer.Put (bytes, 0, bytes.Length);
				BytesIn++;
			}
			if(_procBuffer.Length > 0) {
				_procBuffer.TakeTo (Binding, 1);
				BytesOut++;
			}
		}

		public override int ReadByte () {
			CheckIfAllowed (false);
			if (_inStreamEnded)
				return -1;

			if(_procBuffer.Length < 1) {
				var bytesRead = FillAndProcessBuffer ();
				_procBuffer.Put (_outBuffer, 0, bytesRead);
			}

			if(_procBuffer.Length > 1) {
				var outByte = _procBuffer.Take ();
				BytesOut++;
				return outByte;
			} else {
				return -1;
			}
		}

		public override int Read (byte[] buffer, int offset, int count) {
			CheckIfAllowed (false);

			var copiedOut = 0;
			while (_procBuffer.Length < count && !_inStreamEnded) {
				// Read and process a block/stride
				var bytesProcessed = FillAndProcessBuffer ();
				// Put the processed bytes in the procbuffer
				_procBuffer.Put (_outBuffer, 0, bytesProcessed);
				// Prevent procbuffer overflow where applicable
				if(_procBuffer.Spare < count) {
					var overflowOut = _procBuffer.Length;
					_procBuffer.Take (buffer, offset, overflowOut);
					offset += overflowOut;
					count -= overflowOut;
					copiedOut += overflowOut;

					BytesOut += overflowOut;
				}
			}
			var copyOut = Math.Min (count, _procBuffer.Length);
			_procBuffer.Take (buffer, offset, copyOut);
			copiedOut += copyOut;

			BytesOut += copyOut;

			return copiedOut;
		}

		/// <summary>
		/// Fills the read buffer with a single block/stride of input. Increments 'BytesIn' property.
		/// </summary>
		/// <returns>The read buffer.</returns>
		private int FillAndProcessBuffer() {
			var bytesRead = 0;
			do {
				var iterRead = Binding.Read(_inBuffer, bytesRead, _inBuffer.Length - bytesRead);
				if (iterRead < 1) {
					_inStreamEnded = true;
					break;
				}
				bytesRead += iterRead;
			} while (bytesRead < _inBuffer.Length);

			BytesIn += bytesRead;

			if (_inStreamEnded) {
				return FinishReading (bytesRead);
			} else {
				return _cipher.ProcessBytes (_inBuffer, 0, bytesRead, _outBuffer, 0);
			}
		}

		/// <summary>
		/// Finishes the writing/encryption operation, processing the final block/stride.
		/// </summary>
		/// <returns>Size of final block written.</returns>
		/// <exception cref="DataLengthException">Thrown when final bytes could not be written to the output.</exception>
		private void FinishWriting() {
			byte[] finalBytes = null;
			try {
				finalBytes = _cipher.DoFinal ();
			} catch (DataLengthException dlEx) {
				if(String.Equals(dlEx.Message, "output buffer too short")) {
					throw new DataLengthException(WritingError);
				} else if(String.Equals(dlEx.Message, "need at least one block of input for CTS")) {
					throw new DataLengthException(ShortCTSError);
				} else {
					throw new DataLengthException (UnknownFinaliseError, dlEx);
				}
			} catch (Exception ex) {
				throw new Exception(UnknownFinaliseError, ex);
			}
			// Write out the final block
			Binding.Write (finalBytes, 0, finalBytes.Length);
			BytesOut += finalBytes.Length;
		}

		/// <summary>
		/// Finishes the decryption/reading operation, processing the final block/stride. 
		/// Majority of integrity checking happens here.
		/// </summary>
		/// <returns>The number of bytes in the final block/stride.</returns>
		/// <exception cref="PaddingException">Thrown when no padding, malformed padding, or misaligned padding is found.</exception>
		/// <exception cref="IncompleteBlockException">Thrown when ciphertext is not a multiple of block size (unexpected length).</exception>
		/// <exception cref="AuthenticationException">Thrown when MAC/authentication check fails to match with expected value. AEAD-relevant.</exception>
		/// <exception cref=""></exception>
		private int FinishReading(int length) {
			var finalBytes = 0;
			try {
				if(_cipher is CtsBlockCipher) _outBuffer = new byte[_outBuffer.Length * 2];
				finalBytes = _cipher.DoFinal(_inBuffer, 0, length, _outBuffer, 0);
			} catch (DataLengthException dlEx) {
				if (_cipher is IAeadBlockCipher) {
					// No example here, but leaving it here anyway for possible future implementation.
				} else if (_cipher is PaddedBufferedBlockCipher) {
					switch (dlEx.Message) {
					case "last block incomplete in decryption":
						throw new PaddingException (UnexpectedLengthError);
					default:
						throw new PaddingException ("The ciphertext padding is corrupt.");
					}
				//} else if (_cipher is CtsBlockCipher) {

				} else if (_cipher is BufferedBlockCipher) {
					switch (dlEx.Message) {
					case "data not block size aligned":
						throw new IncompleteBlockException (UnexpectedLengthError);
					default:
						throw new DataLengthException (UnknownFinaliseError, dlEx);
					}
				} else {
					// No example here, but leaving it here anyway for possible future implementation.
				}
			} catch (InvalidCipherTextException ctEx) {
				if (_cipher is IAeadBlockCipher) {
					switch (ctEx.Message) {
					case "data too short":
						throw new IncompleteBlockException ();
					case "mac check in GCM failed":
					case "mac check in EAX failed":
						throw new AuthenticationException ("The calculated MAC for the ciphertext is different to the supplied MAC.");
					}
				} else if(_cipher is PaddedBufferedBlockCipher) {
					switch (ctEx.Message) {
					case "pad block corrupted":
						throw new PaddingException ();
					default:
						throw new InvalidCipherTextException (UnknownFinaliseError, ctEx);
					}
				} else if (_cipher is BufferedBlockCipher) {
					throw new InvalidCipherTextException(UnknownFinaliseError, ctEx);
				} else {
					// No example here, but leaving it here anyway for possible future implementation.
				}
			}

			base.Finish ();
			return finalBytes;
		}

		/// <summary>
		/// Finish the decoration operation, whatever that constitutes in a derived implementation. 
		/// Could be done before a close or reset.
		/// </summary>
		protected override void Finish () {
			if (Finished)
				return;
			if (Encrypting)
				FinishWriting ();

			base.Finish ();
		}

		protected override void Reset (bool finish = false) {
			Array.Clear (_inBuffer, 0, _inBuffer.Length);
			Array.Clear (_outBuffer, 0, _outBuffer.Length);
			_procBuffer.Erase ();
			_cipher.Reset ();
			base.Reset (finish);
		}

		protected override void Dispose (bool disposing) {
			if (!_disposed) {
				if (disposing) {
					// dispose managed resources
					Finish ();
					_cipher.Reset();
					this._cipher = null;
					base.Dispose (disposing);
					_disposed = true;
				}
			}
		}
	}
}
