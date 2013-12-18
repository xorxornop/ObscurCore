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
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Modes;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;
using ObscurCore.Information;

namespace ObscurCore.Cryptography
{
	/// <summary>
	/// Decorating stream implementing encryption/decryption operations by a symmetric cipher.
	/// </summary>
	public sealed class SymmetricCryptoStream : DecoratingStream
	{
		/// <summary>
		/// What mode is active - encryption or decryption?
		/// </summary>
		public bool Encrypting {
			get { return base.Writing; }
		}

		private ICipherWrapper _cipher;
	    private readonly RingByteBuffer _writeBuffer, _readBuffer;
		private readonly byte[] _inBuffer;
		private byte[] _outBuffer; // non-readonly allows for on-the-fly reassignment for CTS compat. during finalisation.

	    private byte[] _operationBuffer;
	    private int _operationBufferOffset;

	    private int _operationSize;

		private bool _inStreamEnded;
		private bool _disposed;

		private const string UnknownFinaliseError = "An unknown type of error occured while transforming the final block of ciphertext.";
		private const string UnexpectedLengthError = "The data in the ciphertext is not the expected length.";
		private const string WritingError = "Could not write transformed block bytes to output stream.";
		private const string ShortCtsError = "Insufficient input length. CTS mode block ciphers require at least one block.";

	    private static readonly byte[] EmptyByteArray = {};


	    public SymmetricCryptoStream(Stream binding, bool encrypting, SymmetricCipherConfiguration config)
	        : this(binding, encrypting, config, null, true) {}

	    /// <summary>Initialises the stream and its associated cipher for operation automatically from provided configuration object.</summary>
		/// <param name="binding">Stream to be written/read to/from.</param>
		/// <param name="encrypting">Specifies whether the stream is for writing (encrypting) or reading (decryption).</param>
		/// <param name="config">Configuration object describing how to set up the internal cipher and associated services.</param>
		/// <param name="key">Derived cryptographic key for the internal cipher to operate with. Overrides key in configuration.</param>
		/// <param name="closeOnDispose">Set to <c>true</c> to also close the base stream when closing, or vice-versa.</param>
		public SymmetricCryptoStream (Stream binding, bool encrypting, SymmetricCipherConfiguration config, 
		                              byte[] key, bool closeOnDispose) : base(binding, encrypting, closeOnDispose, true)
		{
            if ((config.Key.IsNullOrZeroLength()) && (key.IsNullOrZeroLength())) 
                throw new ArgumentException("No key provided in field in configuration object or as parameter.");

			ICipherParameters cipherParams = null;

            byte[] workingKey = key ?? config.Key;

		    switch (config.Type) {
                case SymmetricCipherType.None:
					throw new ConfigurationInvalidException("Type: None/null value is never set in a valid cipher configuration.");
		        case SymmetricCipherType.Block:
                case SymmetricCipherType.Aead:

                    SymmetricBlockCipher blockCipherEnum;
		            try {
		                blockCipherEnum = config.CipherName.ToEnum<SymmetricBlockCipher>();
		            } catch (EnumerationValueUnknownException e) {
						throw new ConfigurationValueInvalidException("Cipher unknown/unsupported.", e);
		            }

                    if(!workingKey.Length.Equals(config.KeySizeBits / 8))
                        throw new InvalidDataException("Key is not of the declared length.");
                    if(!Athena.Cryptography.BlockCiphers[blockCipherEnum].AllowableBlockSizes.Contains(config.BlockSizeBits)) 
                        throw new NotSupportedException("Specified block size is unsupported.");

                    base.BufferRequirementOverride = (config.BlockSizeBits / 8) * 2;

                    var blockCipher = Source.CreateBlockCipher(blockCipherEnum, config.BlockSizeBits);

		            switch (config.Type) {
                        case SymmetricCipherType.Block:

		                    var blockWrapper = new BlockCipherConfigurationWrapper(config);

		                    BlockCipherMode blockModeEnum = blockWrapper.Mode;
		                    byte[] blockIV = blockWrapper.IV;

		                    cipherParams = Source.CreateBlockCipherParameters(blockCipherEnum, workingKey, blockIV);
                            // Overlay the cipher with the mode of operation
                            blockCipher = Source.OverlayBlockCipherWithMode(blockCipher, blockModeEnum,
				                config.BlockSizeBits);

                            IBlockCipherPadding padding = null;
                            BlockCipherPadding paddingEnum = blockWrapper.Padding;
		                    if (paddingEnum == BlockCipherPadding.None) {
		                        if (Athena.Cryptography.BlockCipherModes[blockModeEnum]
		                            .PaddingRequirement == PaddingRequirement.Always) {
		                            throw new NotSupportedException(
		                                "Cipher configuration does not specify the use of padding, " +
		                                    "which is required for the specified mode of operation.");
		                        }
		                    } else {
		                        padding = Source.CreatePadding(paddingEnum);
		                    }
                            blockCipher.Init(encrypting, cipherParams);

                            _cipher = new BlockCipherWrapper(encrypting, blockCipher, padding);

		                    break;
		                case SymmetricCipherType.Aead:

                            AeadBlockCipherMode aeadModeEnum;
		                    try {
		                        aeadModeEnum = config.ModeName.ToEnum<AeadBlockCipherMode>();
		                    } catch (EnumerationValueUnknownException e) {
								throw new ConfigurationValueInvalidException("AEAD mode unknown/unsupported.", e);
		                    }

                            cipherParams = Source.CreateAeadBlockCipherParameters(blockCipherEnum,
				                workingKey, config.IV, config.MacSizeBits, config.AssociatedData);
                            // Overlay the cipher with the mode of operation
					        var aeadCipher = Source.OverlayBlockCipherWithAeadMode(blockCipher, aeadModeEnum);

					        // Create the I/O-enabled transform object
					        if (!String.IsNullOrEmpty(config.PaddingName) && !config.PaddingName.Equals(BlockCipherPadding.None.ToString()))
						        throw new NotSupportedException("Padding was specified for use in AEAD mode - it is not allowed and unnecessary.");

                            aeadCipher.Init(encrypting, cipherParams);
					        //_cipher = new BufferedAeadBlockCipher(aeadCipher);
                            _cipher = new AeadCipherWrapper(encrypting, aeadCipher);

		                    break;
		            }
		            break;
		        case SymmetricCipherType.Stream:

		            var streamWrapper = new StreamCipherConfigurationWrapper(config);

		            var streamCipherEnum = streamWrapper.StreamCipher;
		            var streamNonce = streamWrapper.Nonce;
                    //base.BufferRequirementOverride = !streamNonce.IsNullOrZeroLength() ? (streamNonce.Length) * 2 : streamWrapper.KeySizeBytes * 2;
		            base.BufferRequirementOverride = 64;

				    // Requested a stream cipher.
                    cipherParams = Source.CreateStreamCipherParameters(streamCipherEnum, workingKey, streamNonce);
				    // Instantiate the cipher
				    var streamCipher = Source.CreateStreamCipher(streamCipherEnum);
				    // Create the I/O-enabled transform object
				    //_cipher = new BufferedStreamCipher(streamCipher);

		            break;
		        default:
		            throw new ArgumentException("Not a valid cipher configuration.");
		    }

			// Initialise the buffers 
			_inBuffer = new byte[_cipher.OperationSize];
			_outBuffer = new byte[_cipher.OperationSize];
			_procBuffer = new RingByteBuffer (_cipher.OperationSize << 8);
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
            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            }
            if (buffer.Length < offset + count) {
                throw new ArgumentException("Insufficient data.", "count");
            }

            // Process any leftovers
            if (_operationBufferOffset > 0 && count > 0) {
                Array.Copy(buffer, offset, _operationBuffer, _operationBufferOffset, 
                    _operationSize - _operationBufferOffset);
                var processed = _cipher.ProcessBytes(_operationBuffer, 0, _outBuffer, 0);
                _operationBufferOffset -= processed;
                offset -= processed;
                count -= processed;
                _writeBuffer.Put(_outBuffer, 0, processed);
            }

		    while (count > _operationSize) {
		        // Process and put the resulting bytes in procbuffer
				var processed = _cipher.ProcessBytes(buffer, offset, _outBuffer, 0);
                offset += _operationSize;
				count -= _operationSize;
				BytesIn += _operationSize;
				_writeBuffer.Put (_outBuffer, 0, processed);
				
                // Prevent possible writebuffer overflow
				if(_writeBuffer.Spare < _operationSize) {
					var overflowOut = _writeBuffer.Length;
					// Write out the processed data to the stream binding
					_writeBuffer.TakeTo (Binding, overflowOut);
					BytesOut += overflowOut;
				}
		    }

            // Store any remainder in operation buffer
            Array.Copy(buffer, offset, _operationBuffer, _operationBufferOffset, count);

            // Write out the processed data to the stream binding
			var writeOut = _writeBuffer.Length;
			_writeBuffer.TakeTo (Binding, writeOut);
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

        /// <summary>
        /// Read the precise number of bytes specified. Not guaranteed to return the same quantity; 
        /// only ensures that the stream source binding has a precise number of bytes read. 
        /// Buffer must accomodate count + OperationLength quantity of bytes.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public void ReadPrecise(byte[] buffer, int offset, int count) {

            // TODO: Finish method

            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            } else if (count == 0) {
                return;
            }

            if (_operationBufferOffset > 0) {
                var read = Binding.Read(_operationBuffer, _operationBufferOffset, _operationSize - _operationBufferOffset);
                _operationBufferOffset -= _operationSize - read;
                if (_operationBufferOffset > 0) {
                    throw new DataLengthException("Could not read expected quantity (leftover fill step).");
                }
                count -= read;
                offset += _cipher.ProcessBytes(_operationBuffer, 0, buffer, offset);
            }



            int remainder;
            int operations = Math.DivRem(count, _operationSize, out remainder);

            for (int i = 0; i < operations; i++) {
                int bytesRead = Binding.Read(_operationBuffer, _operationBufferOffset, _operationSize);
                if (bytesRead < _operationSize) {
                    throw new DataLengthException("Could not read expected quantity.");
                }
                offset += _cipher.ProcessBytes(_operationBuffer, 0, buffer, offset);
            }

            // Any leftover/remainder bytes are stored (they are non-decrypted, so far)
            int remainderRead = Binding.Read(_operationBuffer, _operationBufferOffset, remainder);
            if (remainderRead > remainder) {
                
            }
            _operationBufferOffset = remainderRead;
            

            BytesIn += count;

        }


	    public override int Read (byte[] buffer, int offset, int count) {
			CheckIfAllowed (false);


            // TODO: Redo method. Use ReadPrecise as a prototype


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

			return _inStreamEnded ? FinishReading (bytesRead) : _cipher.ProcessBytes (_inBuffer, 0, bytesRead, _outBuffer, 0);
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
					throw new DataLengthException(ShortCtsError);
				} else {
					throw new DataLengthException (UnknownFinaliseError, dlEx);
				}
			} catch (Exception ex) {
				//throw new Exception(UnknownFinaliseError, ex);
			    throw;
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
		/// <exception cref="PaddingDataException">Thrown when no padding, malformed padding, or misaligned padding is found.</exception>
		/// <exception cref="IncompleteBlockException">Thrown when ciphertext is not a multiple of block size (unexpected length).</exception>
		/// <exception cref="CiphertextAuthenticationException">Thrown when MAC/authentication check fails to match with expected value. AEAD-relevant.</exception>
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
						throw new PaddingDataException (UnexpectedLengthError);
					default:
						throw new PaddingDataException ("The ciphertext padding is corrupt.");
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
						throw new CiphertextAuthenticationException ("The calculated MAC for the ciphertext is different to the supplied MAC.");
					}
				} else if(_cipher is PaddedBufferedBlockCipher) {
					switch (ctEx.Message) {
					case "pad block corrupted":
						throw new PaddingDataException ();
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
		    if (_disposed) return;
		    if (!disposing) return;
		    // dispose managed resources
		    Finish ();
		    _cipher.Reset();
		    this._cipher = null;
		    base.Dispose (true);
		    _disposed = true;
		}
	}
}
