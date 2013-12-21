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

		private byte[] _operationBuffer; // primary buffer
		private int _operationBufferOffset;

		private byte[] _tempBuffer;
		private readonly RingByteBuffer _outBuffer;



	    private int _operationSize;

		private bool _inStreamEnded;
		private bool _disposed;

		private const string UnknownFinaliseError = "An unknown type of error occured while transforming the final block of ciphertext.";
		private const string UnexpectedLengthError = "The data in the ciphertext is not the expected length.";
		private const string WritingError = "Could not write transformed block bytes to output stream.";


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

					base.BufferSizeRequirement = (config.BlockSizeBits / 8) * 2;
					
					var blockWrapper = new BlockCipherConfigurationWrapper(config);

				var blockCipher = Source.CreateBlockCipher(blockCipherEnum, blockWrapper.BlockSizeBits);

					

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
							.PaddingRequirement == PaddingRequirement.Always)
						{
							throw new NotSupportedException(
								"Cipher configuration does not specify the use of padding, " +
								"which is required for the specified mode of operation.");
						}
					} else {
						padding = Source.CreatePadding(paddingEnum);
						padding.Init(StratCom.EntropySource);
					}
					
					blockCipher.Init(encrypting, cipherParams);
					_cipher = new BlockCipherWrapper(encrypting, blockCipher, padding);
					
		            break;
				case SymmetricCipherType.Stream:

					var streamWrapper = new StreamCipherConfigurationWrapper (config);

					var streamCipherEnum = streamWrapper.StreamCipher;
					var streamNonce = streamWrapper.Nonce;
					//base.BufferSizeRequirement = !streamNonce.IsNullOrZeroLength() ? (streamNonce.Length) * 2 : streamWrapper.KeySizeBytes * 2;
					base.BufferSizeRequirement = 64;

					// Requested a stream cipher.
					cipherParams = Source.CreateStreamCipherParameters (streamCipherEnum, workingKey, streamNonce);
					// Instantiate the cipher
					var streamCipher = Source.CreateStreamCipher (streamCipherEnum);
					streamCipher.Init (encrypting, cipherParams);
					_cipher = new StreamCipherWrapper (encrypting, streamCipher, strideIncreaseFactor : 2);

		            break;
		        default:
		            throw new ArgumentException("Not a valid cipher configuration.");
		    }

			// Initialise the buffers 
			//_inBuffer = new byte[_cipher.OperationSize];
			//_outBuffer = new byte[_cipher.OperationSize];

			_operationSize = _cipher.OperationSize;
			_operationBuffer = new byte[_operationSize];
			_tempBuffer = new byte[_operationSize * 2];
			_operationBufferOffset = 0;
			if(encrypting) {
				_outBuffer = new RingByteBuffer (_cipher.OperationSize << 8);
			} else {
				_outBuffer = new RingByteBuffer (_cipher.OperationSize << 2);
			}


			//_procBuffer = new RingByteBuffer (_cipher.OperationSize << 8);
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

		/// <summary>
		/// Writes specified quantity of bytes exactly (after decoration transform)
		/// </summary>
		/// <param name="source">Source.</param>
		/// <param name="length">Length.</param>
		/// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
		public override long WriteExactlyFrom (Stream source, long length) {
			CheckIfAllowed (true);
			if(source == null) {
				throw new ArgumentNullException ("source");
			}

			int totalIn = 0, totalOut = 0;
			int iterIn = 0, iterOut = 0;

			// Process any remainder
			if (_operationBufferOffset > 0 && length > _operationSize) {
				var gapLength = _operationSize - _operationBufferOffset;

				iterIn = source.Read (_operationBuffer, _operationBufferOffset, gapLength);
				if(iterIn > gapLength) {
					throw new EndOfStreamException ();
				}

				totalIn += iterIn;
				iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
				_operationBufferOffset = 0;
				length -= iterOut;
				_outBuffer.Put(_tempBuffer, 0, iterOut);
			}

			while(totalOut + _outBuffer.Length < length) {
				if(source.Read (_operationBuffer, _operationBufferOffset, _operationSize) > _operationSize) {
					throw new EndOfStreamException ();
				}
				totalIn += _operationSize;
				iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
				_outBuffer.Put (_tempBuffer, 0, iterOut);

				// Prevent possible writebuffer overflow
				if(_outBuffer.Spare < _operationSize) {
					iterOut = _outBuffer.Length;
					// Write out the processed data to the stream binding
					_outBuffer.TakeTo (Binding, iterOut);
					totalOut += iterOut;
				}
			}

			// Write out the processed data to the stream binding
			iterOut = (int) (length - totalOut);
			_outBuffer.TakeTo (Binding, iterOut);
			BytesOut += iterOut + totalOut;

			return totalIn;
		}


		public override void Write (byte[] buffer, int offset, int count) {
			CheckIfAllowed (true);
			if (buffer == null) {
				throw new ArgumentNullException("buffer");
			}
			if (buffer.Length < offset + count) {
				throw new ArgumentException("Insufficient data.", "count");
			}

			int totalIn = 0, totalOut = 0;
			int iterOut = 0;

			// Process any leftovers
			var gapLength = _operationSize - _operationBufferOffset;
			if (_operationBufferOffset > 0 && count > gapLength) {
				Array.Copy(buffer, offset, _operationBuffer, _operationBufferOffset, 
					gapLength);
				totalIn += gapLength;
				iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
				_operationBufferOffset = 0;
				offset += gapLength;
				count -= gapLength;
				_outBuffer.Put(_tempBuffer, 0, iterOut);
			}

			if (count < 0)
				return;

			int remainder;
			var operations = Math.DivRem(count, _operationSize, out remainder);

			for (var i = 0; i < operations; i++) {
				iterOut = _cipher.ProcessBytes(buffer, offset, _tempBuffer, 0);
				totalIn += _operationSize;
				offset += _operationSize;
				_outBuffer.Put (_tempBuffer, 0, iterOut);

				// Prevent possible writebuffer overflow
				if(_outBuffer.Spare < _operationSize) {
					iterOut = _outBuffer.Length;
					// Write out the processed data to the stream binding
					_outBuffer.TakeTo (Binding, iterOut);
					totalOut += iterOut;
				}
			}

			// Store any remainder in operation buffer
			Array.Copy(buffer, offset, _operationBuffer, _operationBufferOffset, remainder);
			totalIn += remainder;
			_operationBufferOffset += remainder;

			// Write out the processed data to the stream binding
			iterOut = _outBuffer.Length - _operationSize;
			if(iterOut > 0) {
				//iterOut = _outBuffer.Length; 
				_outBuffer.TakeTo (Binding, iterOut);
				BytesOut += iterOut + totalOut;
			}
		}

		/// <summary>
		/// Writes a byte. Not guaranteed or likely to be written out immediately. 
		/// If writing precision is required, do not use this wherever possible.
		/// </summary>
		/// <param name="b">The blue component.</param>
		public override void WriteByte (byte b) {
			CheckIfAllowed (true);
			if (Finished)
				return;

			if (_operationBufferOffset == _operationSize) {
				var iterOut = _cipher.ProcessBytes (_operationBuffer, 0, _tempBuffer, 0);
				_outBuffer.Put (_tempBuffer, 0, iterOut);
			} else {
				_operationBuffer[_operationBufferOffset++] = b;
			}

			_outBuffer.TakeTo (Binding, 1);
		}

		// Reading

		public override int ReadByte () {
			CheckIfAllowed (false);
			if (_inStreamEnded)
				return -1;

			if (_operationBufferOffset == _operationSize) {
				// Op buffer is full, process an op block
				var iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
				_outBuffer.Put (_tempBuffer, 0, iterOut);
				_operationBufferOffset = 0;
			}
			_operationBuffer[_operationBufferOffset++] = (byte)Binding.ReadByte();

			if(_outBuffer.Length == 0) {
				throw new InvalidOperationException ();
			}
			return _outBuffer.Take();
		}

		/// <summary>
		/// Read the specified buffer, offset and count. 
		/// Guaranteed to read 'count' bytes.
		/// </summary>
		/// <returns>Quantity of bytes read into supplied buffer array.</returns>
		/// <param name="buffer">Buffer.</param>
		/// <param name="offset">Offset.</param>
		/// <param name="count">Count.</param>
	    public override int Read (byte[] buffer, int offset, int count) {
			CheckIfAllowed (false);
			if (Finished)
				return 0;
			if (buffer == null) {
				throw new ArgumentNullException ("buffer");
			} else if (buffer.Length < offset + count) {

			}

			int totalIn = 0, totalOut = 0;
			int iterIn = 0, iterOut = 0;

			// Has ReadByte been used? If it has then we need to return the partial block
			if(_outBuffer.Length > 0) {
				iterOut = _outBuffer.Length;
				if(buffer.Length < offset + iterOut) {
					throw new DataLengthException ("Buffer insufficient length to accomodate data.");
				}
				_outBuffer.Take (buffer, offset, iterOut);
				totalOut += iterOut;
				offset += iterOut;
				count -= iterOut;
			}

			// Process any remainder bytes from last call, if any, by filling the block/operation
			if (_operationBufferOffset > 0) {
				iterIn = Binding.Read(_operationBuffer, _operationBufferOffset, _operationSize - _operationBufferOffset);
				totalIn += iterIn;
				_operationBufferOffset -= _operationSize - iterIn;

				// End of stream detection
				if (_operationBufferOffset > 0) {
					totalOut += FinishReading (_operationBuffer, 0, iterIn, buffer, offset);
					BytesIn += totalIn;
					BytesOut += totalOut;
					return totalOut;
				}

				iterOut = _cipher.ProcessBytes(_operationBuffer, 0, buffer, offset);
				count -= iterOut;
				offset += iterOut;
				totalOut += iterOut;
			}

			int remainder;
			var operations = Math.DivRem(count, _operationSize, out remainder);

			// Process all the whole blocks/operations
			for (var i = 0; i < operations; i++) {
				iterIn = Binding.Read(_operationBuffer, 0, _operationSize);
				totalIn += iterIn;
				// End of stream detection
				if (iterIn < _operationSize) {
					totalOut += FinishReading(_operationBuffer, 0, iterIn, buffer, offset);
					BytesIn += totalIn;
					BytesOut += totalOut;
					return totalOut;
				}
				iterOut = _cipher.ProcessBytes(_operationBuffer, 0, buffer, offset);
				totalOut += iterOut;
				offset += iterOut;
			}

			// Any remainder bytes are stored (not decrypted)
			if (remainder > 0) {
				_operationBufferOffset = Binding.Read(_operationBuffer, _operationBufferOffset, remainder);
				totalIn += _operationBufferOffset;
				// End of stream detection
				if (_operationBufferOffset < remainder) {
					totalOut += FinishReading (_operationBuffer, 0, _operationBufferOffset, buffer, offset);
				}
			}

			BytesIn += totalIn;
			BytesOut += totalOut;
			return totalOut;
		}



		public override long ReadExactlyTo (Stream destination, long length) {
			CheckIfAllowed (false);
			if (Finished)
				return 0;
			if (destination == null) {
				throw new ArgumentNullException ("destination");
			}

			int totalIn = 0, totalOut = 0;
			int iterIn = 0, iterOut = 0;

			// Write out any partial completed block(s)
			if(_outBuffer.Length > 0) {
				iterOut = _outBuffer.Length;
				_outBuffer.TakeTo (destination, iterOut);
				totalOut += iterOut;
				// No read took place, so no subtraction of length appropriate
			}

			// Process any remainder bytes from last call, if any, by filling the block/operation
			if (_operationBufferOffset > 0) {
				iterIn = Binding.Read(_operationBuffer, _operationBufferOffset, _operationSize - _operationBufferOffset);
				totalIn += iterIn;
				_operationBufferOffset -= _operationSize - iterIn;
				// End of stream detection
				if (_operationBufferOffset > 0) {
					totalOut += FinishReading (_operationBuffer, 0, iterIn, _tempBuffer, 0);
					BytesIn += totalIn;
					BytesOut += totalOut;
					return totalOut;
				} else {
					iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
				}
				length -= iterOut;
			}

			long remainder;
			var operations = Math.DivRem(length, (long)_operationSize, out remainder);

			// Process all the whole blocks/operations
			for (var i = 0; i < operations; i++) {
				iterIn = Binding.Read(_operationBuffer, _operationBufferOffset, _operationSize);
				totalIn += iterIn;
				// End of stream detection
				if (iterIn < _operationSize) {
					totalOut += FinishReading(_operationBuffer, 0, iterIn, _tempBuffer, 0);
					BytesIn += totalIn;
					BytesOut += totalOut;
					return totalOut;
				}
				iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
				totalOut += iterOut;
			}

			// Any remainder bytes are stored (not decrypted)
			if (remainder > 0) {
				_operationBufferOffset = Binding.Read(_operationBuffer, _operationBufferOffset, (int)remainder);
				totalIn += _operationBufferOffset;
				// End of stream detection
				if (_operationBufferOffset < remainder) {
					iterOut = FinishReading (_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
					totalOut += iterOut;
					destination.Write (_tempBuffer, 0, iterOut);
				}
			}

			BytesIn += totalIn;
			BytesOut += totalOut;
			return totalOut;
		}



		/// <summary>
		/// Finishes the writing/encryption operation, processing the final block/stride.
		/// </summary>
		/// <returns>Size of final block written.</returns>
		/// <exception cref="DataLengthException">Thrown when final bytes could not be written to the output.</exception>
		private void FinishWriting() {
			// Write any partial but complete block(s)
			BytesOut += _outBuffer.Length;
			_outBuffer.TakeTo (Binding, _outBuffer.Length);
			int finalLength;
			try {
				finalLength = _cipher.ProcessFinal(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
			} catch (DataLengthException dlEx) {
				if(String.Equals(dlEx.Message, "output buffer too short")) {
					throw new DataLengthException (WritingError);
				} else {
					throw new DataLengthException (UnknownFinaliseError, dlEx);
				}
			} catch (Exception ex) {
				//throw new Exception(UnknownFinaliseError, ex);
			    throw;
			}
			// Write out the final block
			Binding.Write (_tempBuffer, 0, finalLength);
			BytesOut += finalLength;
		}


		private int FinishReading(byte[] input, int inputOffset, int length, byte[] output, int outputOffset) {
			_inStreamEnded = true;
			int finalByteQuantity = _outBuffer.Length;
			_outBuffer.Take (output, outputOffset, finalByteQuantity);
			outputOffset += finalByteQuantity;
			try {
				finalByteQuantity += _cipher.ProcessFinal (input, inputOffset, length, output, outputOffset);
			} catch (Exception ex) {
				throw;
			}

			base.Finish();
			return finalByteQuantity;
		}


//		/// <summary>
//		/// Finishes the decryption/reading operation, processing the final block/stride. 
//		/// Majority of integrity checking happens here.
//		/// </summary>
//		/// <returns>The number of bytes in the final block/stride.</returns>
//		/// <exception cref="PaddingDataException">Thrown when no padding, malformed padding, or misaligned padding is found.</exception>
//		/// <exception cref="IncompleteBlockException">Thrown when ciphertext is not a multiple of block size (unexpected length).</exception>
//		/// <exception cref="CiphertextAuthenticationException">Thrown when MAC/authentication check fails to match with expected value. AEAD-relevant.</exception>
//		/// <exception cref=""></exception>
//		private int FinishReading(int length) {
//			var finalBytes = 0;
//			try {
//				if(_cipher is CtsBlockCipher) _outBuffer = new byte[_outBuffer.Length * 2];
//				finalBytes = _cipher.DoFinal(_inBuffer, 0, length, _outBuffer, 0);
//			} catch (DataLengthException dlEx) {
//				if (_cipher is IAeadBlockCipher) {
//					// No example here, but leaving it here anyway for possible future implementation.
//				} else if (_cipher is PaddedBufferedBlockCipher) {
//					switch (dlEx.Message) {
//					case "last block incomplete in decryption":
//						throw new PaddingDataException (UnexpectedLengthError);
//					default:
//						throw new PaddingDataException ("The ciphertext padding is corrupt.");
//					}
//				//} else if (_cipher is CtsBlockCipher) {
//
//				} else if (_cipher is BufferedBlockCipher) {
//					switch (dlEx.Message) {
//					case "data not block size aligned":
//						throw new IncompleteBlockException (UnexpectedLengthError);
//					default:
//						throw new DataLengthException (UnknownFinaliseError, dlEx);
//					}
//				} else {
//					// No example here, but leaving it here anyway for possible future implementation.
//				}
//			} catch (InvalidCipherTextException ctEx) {
//				if (_cipher is IAeadBlockCipher) {
//					switch (ctEx.Message) {
//					case "data too short":
//						throw new IncompleteBlockException ();
//					case "mac check in GCM failed":
//					case "mac check in EAX failed":
//						throw new CiphertextAuthenticationException ("The calculated MAC for the ciphertext is different to the supplied MAC.");
//					}
//				} else if(_cipher is PaddedBufferedBlockCipher) {
//					switch (ctEx.Message) {
//					case "pad block corrupted":
//						throw new PaddingDataException ();
//					default:
//						throw new InvalidCipherTextException (UnknownFinaliseError, ctEx);
//					}
//				} else if (_cipher is BufferedBlockCipher) {
//					throw new InvalidCipherTextException(UnknownFinaliseError, ctEx);
//				} else {
//					// No example here, but leaving it here anyway for possible future implementation.
//				}
//			}
//
//			base.Finish ();
//			return finalBytes;
//		}

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
			Array.Clear (_operationBuffer, 0, _operationBuffer.Length);
			_operationBufferOffset = 0;
			Array.Clear (_tempBuffer, 0, _tempBuffer.Length);
			_outBuffer.Erase ();



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
