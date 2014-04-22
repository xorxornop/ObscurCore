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
using System.IO;
using System.Linq;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;
using RingByteBuffer;

namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    /// Decorating stream implementing encryption/decryption operations by a symmetric cipher.
    /// </summary>
    public sealed class CipherStream : DecoratingStream
    {
        private const string UnknownFinaliseError = "An unknown type of error occured while transforming the final block of ciphertext.";
        //		private const string UnexpectedLengthError = "The data in the ciphertext is not the expected length.";
        private const string WritingError = "Could not write transformed block bytes to output stream.";

        private const string NotWritingError = "Stream is configured for encryption, and so may only be written to.";
        private const string NotReadingError = "Stream is configured for decryption, and so may only be read from.";

        /// <summary>
        /// What mode is active - encryption or decryption?
        /// </summary>
        public bool Encrypting {
            get { return base.Writing; }
        }

        private readonly ICipherWrapper _cipher;

        private readonly byte[] _operationBuffer; // primary buffer
        private int _operationBufferOffset;
        private readonly int _operationSize;

        private readonly byte[] _tempBuffer;
        private readonly RingBuffer _outBuffer;

        /// <summary>Initialises the stream and its associated cipher for operation automatically from provided configuration object.</summary>
        /// <param name="binding">Stream to be written/read to/from.</param>
        /// <param name="encrypting">Specifies whether the stream is for writing (encrypting) or reading (decryption).</param>
        /// <param name="config">Configuration object describing how to set up the internal cipher and associated services.</param>
        /// <param name="key">Derived cryptographic key for the internal cipher to operate with. Overrides key in configuration.</param>
        /// <param name="closeOnDispose">Set to <c>true</c> to also close the base stream when closing, or vice-versa.</param>
        public CipherStream (System.IO.Stream binding, bool encrypting, SymmetricCipherConfiguration config,
                                      byte[] key, bool closeOnDispose)
            : base(binding, encrypting, closeOnDispose) {
            if (binding == null)
                throw new ArgumentNullException("binding");
            if (config == null)
                throw new ArgumentNullException("config");
            if (key.IsNullOrZeroLength())
                throw new ArgumentException("No key provided.", "key");

            switch (config.Type) {
                case SymmetricCipherType.None:
                    throw new ConfigurationInvalidException("Type: None/null value is never set in a valid cipher configuration.");
                case SymmetricCipherType.Block:
                    var blockConfigWrapper = new BlockCipherConfigurationWrapper(config);
                    if (key.Length != blockConfigWrapper.KeySizeBytes)
                        throw new ArgumentException("Key is not of the length declared in the cipher configuration.", "key");

                    var blockCipher = CipherFactory.CreateBlockCipher(blockConfigWrapper.BlockCipher, blockConfigWrapper.BlockSizeBits);
                    // Overlay the cipher with the mode of operation
                    blockCipher = CipherFactory.OverlayBlockCipherWithMode(blockCipher, blockConfigWrapper.Mode);
                    IBlockCipherPadding padding = null;
                    BlockCipherPadding paddingEnum = blockConfigWrapper.Padding;
                    if (paddingEnum != BlockCipherPadding.None) {
                        padding = CipherFactory.CreatePadding(paddingEnum);
                        padding.Init(StratCom.EntropySupplier);
                    }
                    blockCipher.Init(encrypting, key, blockConfigWrapper.IV);
                    _cipher = new BlockCipherWrapper(encrypting, blockCipher, padding);

                    break;
                case SymmetricCipherType.Stream:
                    var streamConfigWrapper = new StreamCipherConfigurationWrapper(config);
                    if (key.Length != streamConfigWrapper.KeySizeBytes)
                        throw new ArgumentException("Key is not of the length declared in the cipher configuration.", "key");

                    var streamCipher = CipherFactory.CreateStreamCipher(streamConfigWrapper.StreamCipher);
                    streamCipher.Init(encrypting, key, streamConfigWrapper.Nonce);
                    _cipher = new StreamCipherWrapper(encrypting, streamCipher, strideIncreaseFactor: 2);

                    break;
                default:
                    throw new ArgumentException("Not a valid cipher configuration.");
            }

            // Initialise the buffers 
            _operationSize = _cipher.OperationSize;
            _operationBuffer = new byte[_operationSize];
            _tempBuffer = new byte[_operationSize * 2];
            _outBuffer = new RingBuffer(_cipher.OperationSize << (encrypting ? 8 : 2));
            // Shift left 8 upscales : 8 (64 bits) to 2048 [2kB], 16 (128) to 4096 [4kB], 32 (256) to 8192 [8kB]
            base.BufferSizeRequirement = _operationSize;
        }

        public override bool CanRead {
            get { return !Writing && Binding.CanRead; }
        }

        public override bool CanWrite {
            get { return Writing && Binding.CanWrite; }
        }

        public override bool CanSeek {
            get { return false; }
        }

        public override long Seek (long offset, SeekOrigin origin) {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Writes specified quantity of bytes exactly (after decoration transform)
        /// </summary>
        /// <param name="source">Source.</param>
        /// <param name="length">Length.</param>
        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
        public override long WriteExactlyFrom (System.IO.Stream source, long length) {
            CheckIfCanDecorate();
            if (Writing == false)
                throw new InvalidOperationException(NotWritingError);
            if (source == null) {
                throw new ArgumentNullException("source");
            }

            int totalIn = 0, totalOut = 0;
            int iterIn, iterOut;

            // Process any remainder
            if (_operationBufferOffset > 0 && length > _operationSize) {
                int gapLength = _operationSize - _operationBufferOffset;

                iterIn = source.Read(_operationBuffer, _operationBufferOffset, gapLength);
                if (iterIn > gapLength) {
                    throw new EndOfStreamException();
                }

                totalIn += iterIn;
                iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                _operationBufferOffset = 0;
                length -= iterOut;
                _outBuffer.Put(_tempBuffer, 0, iterOut);
            }

            while (totalOut + _outBuffer.Length < length) {
                // Prevent possible writebuffer overflow
                if (_outBuffer.Spare < _operationSize) {
                    iterOut = _outBuffer.Length;
                    // Write out the processed data to the stream StreamBinding
                    _outBuffer.TakeTo(Binding, iterOut);
                    totalOut += iterOut;
                }

                iterIn = source.Read(_operationBuffer, 0, _operationSize);
                totalIn += iterIn;
                // We might have tried to read past the end simply because of the opsize requirement
                if (iterIn < _operationSize) {
                    _operationBufferOffset = iterIn;
                    int finalLength = _cipher.ProcessFinal(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
                    _outBuffer.Put(_tempBuffer, 0, finalLength);
                    break;
                }
                iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                _outBuffer.Put(_tempBuffer, 0, iterOut);
            }

            // Write out the processed data to the stream StreamBinding
            iterOut = (int)(length - totalOut);
            if (iterOut > 0) {
                _outBuffer.TakeTo(Binding, iterOut);
                totalOut += iterOut;
            }

            BytesOut += totalOut;
            BytesIn += totalIn;

            return totalIn;
        }


        public override void Write (byte[] buffer, int offset, int count) {
            CheckIfCanDecorate();
            if (!Writing)
                throw new InvalidOperationException(NotWritingError);
            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            } else if (buffer.Length < offset + count) {
                throw new DataLengthException();
            }

            int totalIn = 0, totalOut = 0;
            int iterOut = 0;

            // Process any leftovers
            int gapLength = _operationSize - _operationBufferOffset;
            if (_operationBufferOffset > 0 && count > gapLength) {
                buffer.CopyBytes(offset, _operationBuffer, _operationBufferOffset, gapLength);
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
            int operations = Math.DivRem(count, _operationSize, out remainder);

            for (var i = 0; i < operations; i++) {
                iterOut = _cipher.ProcessBytes(buffer, offset, _tempBuffer, 0);
                totalIn += _operationSize;
                offset += _operationSize;
                _outBuffer.Put(_tempBuffer, 0, iterOut);

                // Prevent possible writebuffer overflow
                if (_outBuffer.Spare < _operationSize) {
                    iterOut = _outBuffer.Length;
                    // Write out the processed data to the stream StreamBinding
                    _outBuffer.TakeTo(StreamBinding, iterOut);
                    totalOut += iterOut;
                }
            }

            // Store any remainder in operation buffer
            buffer.CopyBytes(offset, _operationBuffer, _operationBufferOffset, remainder);
            totalIn += remainder;
            _operationBufferOffset += remainder;

            // Write out the processed data to the stream StreamBinding
            iterOut = _outBuffer.Length - _operationSize;
            if (iterOut > 0) {
                //iterOut = _outBuffer.Length; 
                _outBuffer.TakeTo(StreamBinding, iterOut);
                totalOut += iterOut;
            }
            BytesOut += totalOut;
            BytesIn += totalIn;
        }

        /// <summary>
        /// Writes a byte. Not guaranteed or likely to be written out immediately. 
        /// If writing precision is required, do not use this wherever possible.
        /// </summary>
        /// <param name="b">Byte to write.</param>
        public override void WriteByte (byte b) {
            CheckIfCanDecorate();
            if (Writing == false)
                throw new InvalidOperationException(NotWritingError);

            if (_operationBufferOffset < _operationSize) {
                _operationBuffer[_operationBufferOffset++] = b;
            } else {
                var iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                _outBuffer.Put(_tempBuffer, 0, iterOut);
                _operationBufferOffset = 0;
            }

            if (_outBuffer.Length > 0)
                StreamBinding.WriteByte(_outBuffer.Take());
        }

        // Reading

        public override int ReadByte () {
            if (Disposed)
                throw new ObjectDisposedException("Stream has been disposed.");
            if (Finished && _outBuffer.Length == 0)
                return -1;
            if (Writing)
                throw new InvalidOperationException(NotReadingError);

            if (_outBuffer.Length == 0) {
                int toRead = _operationSize - _operationBufferOffset;
                int iterIn = StreamBinding.Read(_operationBuffer, 0, toRead);
                BytesIn += iterIn;
                _operationBufferOffset += iterIn;
                if (iterIn == 0) {
                    int iterOut = FinishReading(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
                    _operationBufferOffset = 0;
                    _outBuffer.Put(_tempBuffer, 0, iterOut);
                    BytesOut++;
                    return _outBuffer.Take();
                }
            }

            if (_operationBufferOffset == _operationSize) {
                // Op buffer is full, process an op block
                int iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                _outBuffer.Put(_tempBuffer, 0, iterOut);
                _operationBufferOffset = 0;
            }

            return _outBuffer.Take();
        }

        /// <summary>
        /// Read and decrypt bytes from the stream StreamBinding into the supplied array. 
        /// Not guaranteed to read 'count' bytes if ReadByte() has been used. 
        /// Guaranteed to return 'count' bytes until end of stream.
        /// </summary>
        /// <returns>Quantity of bytes read into supplied buffer array.</returns>
        /// <param name="buffer">Buffer.</param>
        /// <param name="offset">Offset.</param>
        /// <param name="count">Count.</param>
        /// <exception cref="InvalidOperationException">Stream is encrypting, not decrypting.</exception>
        /// <exception cref="ArgumentNullException">Destination stream is null.</exception>
        /// <exception cref="DataLengthException">Array insufficient size to accept decrypted data.</exception>
        /// <exception cref="EndOfStreamException">Required quantity of bytes could not be read.</exception>
        public override int Read (byte[] buffer, int offset, int count) {
            if (Disposed)
                throw new ObjectDisposedException("Stream has been disposed.");
            if (Finished && _outBuffer.Length == 0)
                return 0;
            if (Writing)
                throw new InvalidOperationException(NotReadingError);
            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            } else if (buffer.Length < offset + count) {
                throw new DataLengthException();
            }

            int totalIn = 0, totalOut = 0;
            int iterIn = 0, iterOut = 0;

            if (_outBuffer.Length > 0) {
                iterOut = Math.Min(_outBuffer.Length, count);
                _outBuffer.Take(buffer, offset, iterOut);
                totalOut += iterOut;
                offset += iterOut;
                count -= iterOut;
            }

            if (Finished == false) {
                while (count > 0) {
                    iterIn = StreamBinding.Read(_operationBuffer, _operationBufferOffset, _operationSize - _operationBufferOffset);
                    if (iterIn > 0) {
                        // Normal processing (mid-stream)
                        _operationBufferOffset += iterIn;
                        totalIn += iterIn;
                        if (_operationBufferOffset == _operationSize) {
                            if (count >= _operationSize) {
                                // Full operation
                                iterOut = _cipher.ProcessBytes(_operationBuffer, 0, buffer, offset);
                                totalOut += iterOut;
                                offset += iterOut;
                                count -= iterOut;
                            } else {
                                // Short operation
                                iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                                int subOp = buffer.Length - offset;
                                _tempBuffer.CopyBytes(0, buffer, offset, subOp);
                                totalOut += subOp;
                                _outBuffer.Put(_tempBuffer, count, iterOut - subOp);
                                count = 0;
                            }
                            _operationBufferOffset = 0;
                        }
                    } else {
                        // End of stream - finish the decryption
                        // Copy the previous operation block in to provide overrun protection
                        buffer.CopyBytes(offset - _operationSize, _tempBuffer, 0, _operationSize);
                        iterOut = FinishReading(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, _operationSize);
                        if (iterOut > 0) {
                            // Process the final decrypted data
                            int remainingBufferSpace = buffer.Length - (offset + iterOut);
                            if (remainingBufferSpace < 0) {
                                // Not enough space in destination buffer
                                int subOp = buffer.Length - offset;
                                _tempBuffer.CopyBytes(_operationSize, buffer, offset, subOp);
                                totalOut += subOp;
                                _outBuffer.Put(_tempBuffer, _operationSize + subOp, iterOut - subOp);
                            } else {
                                _tempBuffer.CopyBytes(_operationSize, buffer, offset, iterOut);
                                totalOut += iterOut;
                            }
                        } else {
                            // We need to modify the existing output because the last block was actually padded!
                            totalOut += iterOut; // iterOut is negative, so this is actually negation
                        }
                        count = 0;
                        _operationBufferOffset = 0;
                    }
                }
            }

            BytesIn += totalIn;
            BytesOut += totalOut;
            return totalOut;
        }


        //		/// <summary>
        //		/// Decrypt an exact amount of bytes from the stream StreamBinding and write them 
        //		/// to a destination stream.
        //		/// </summary>
        //		/// <returns>The quantity of bytes written to the destination stream.</returns>
        //		/// <param name="destination">Stream to write decrypted data to.</param>
        //		/// <param name="length">Quantity of bytes to read.</param>
        //		/// <param name="finishing">
        //		/// If set to <c>true</c>, final ciphertext position is located at end of requested length.
        //		/// </param>
        //		/// <exception cref="InvalidOperationException">Stream is encrypting, not decrypting.</exception>
        //		/// <exception cref="ArgumentNullException">Destination stream is null.</exception>
        //		/// <exception cref="ArgumentException">Length supplied is negative.</exception>
        //		/// <exception cref="EndOfStreamException">Required quantity of bytes could not be read.</exception>
        //		public override long ReadExactlyTo (Stream destination, long length, bool finishing = false) {
        //			CheckIfCanDecorate ();
        //			if (Writing)
        //				throw new InvalidOperationException (NotReadingError);
        //			if (destination == null) {
        //				throw new ArgumentNullException ("destination");
        //			} else if (length < 0) {
        //				throw new ArgumentException ("Length must be positive.", "length");
        //			}
        //
        //			int totalIn = 0, totalOut = 0;
        //			int iterIn = 0, iterOut = 0;
        //
        //			// Has ReadByte been used? If it has then we need to return the partial block
        //			if(_outBuffer.Length > 0) {
        //				iterOut = _outBuffer.Length;
        //				_outBuffer.TakeTo (destination, iterOut);
        //				totalOut += iterOut;
        //			}
        //
        //			while (totalIn < length) {
        //				var remaining = length - totalIn;
        //				int opSize = _operationSize - _operationBufferOffset;
        //				if (opSize > remaining)
        //					opSize = (int)remaining;
        //				iterIn = StreamBinding.Read (_operationBuffer, _operationBufferOffset, opSize);
        //				_operationBufferOffset += iterIn;
        //				totalIn += iterIn;
        ////				length -= iterIn;
        //				if ((finishing && remaining <= _operationSize) || iterIn == 0) {
        //					// Finish the decryption - end of stream
        //					iterOut = FinishReading(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
        //					destination.Write (_tempBuffer, 0, iterOut);
        //					totalOut += iterOut;
        //					_operationBufferOffset = 0;
        //				} else if (_operationBufferOffset == _operationSize) {
        //					// Normal processing (mid-stream)
        //					iterOut = _cipher.ProcessBytes (_operationBuffer, 0, _tempBuffer, 0);
        //					destination.Write (_tempBuffer, 0, iterOut);
        //					totalOut += iterOut;
        //					_operationBufferOffset = 0;
        //				}
        //			}
        //
        //			BytesIn += totalIn;
        //			BytesOut += totalOut;
        //			return totalOut;
        //		}


        /// <summary>
        /// Decrypt an exact amount of bytes from the stream StreamBinding and write them 
        /// to a destination stream.
        /// </summary>
        /// <returns>The quantity of bytes written to the destination stream.</returns>
        /// <param name="destination">Stream to write decrypted data to.</param>
        /// <param name="length">Quantity of bytes to read.</param>
        /// <param name="finishing">
        /// If set to <c>true</c>, final ciphertext position is located at end of requested length.
        /// </param>
        /// <exception cref="InvalidOperationException">Stream is encrypting, not decrypting.</exception>
        /// <exception cref="ArgumentNullException">Destination stream is null.</exception>
        /// <exception cref="ArgumentException">Length supplied is negative.</exception>
        /// <exception cref="EndOfStreamException">Required quantity of bytes could not be read.</exception>
        public override long ReadExactlyTo (System.IO.Stream destination, long length, bool finishing = false) {
            CheckIfCanDecorate();
            if (Writing)
                throw new InvalidOperationException(NotReadingError);
            if (destination == null) {
                throw new ArgumentNullException("destination");
            } else if (length < 0) {
                throw new ArgumentException("Length must be positive.", "length");
            }

            int totalIn = 0, totalOut = 0;
            int iterIn = 0, iterOut = 0;

            // Write out any partial completed block(s)
            int outBufferLength = _outBuffer.Length;
            if (outBufferLength > 0) {
                _outBuffer.TakeTo(destination, outBufferLength);
                totalOut += outBufferLength;
                // No read took place, so no subtraction of length appropriate
            }

            // Process any remainder bytes from last call, if any, by filling the block/operation
            if (_operationBufferOffset > 0) {
                int readLength = _operationSize - _operationBufferOffset;
                if (readLength > length)
                    goto doOperations;
                iterIn = StreamBinding.Read(_operationBuffer, _operationBufferOffset, readLength);
                length -= iterIn;
                totalIn += iterIn;
                // End of stream detection
                if (iterIn < readLength) {
                    throw new EndOfStreamException();
                }
                iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                destination.Write(_tempBuffer, 0, iterOut);
                totalOut += iterOut;
                _operationBufferOffset = 0;
            }
        doOperations:

            long remainderLong;
            int operations = (int)Math.DivRem(length, (long)_operationSize, out remainderLong);
            int remainder = (int)remainderLong;
            // ^ Can be changed back to long if needed.
            // Otherwise, though, we'll try to avoid pointless and costly repeated casts.

            // Process all the whole blocks/operations
            for (int i = 1; i <= operations; i++) {
                iterIn = StreamBinding.Read(_operationBuffer, 0, _operationSize);
                totalIn += iterIn;
                // End of stream detection
                if (iterIn < _operationSize) {
                    BytesIn += totalIn;
                    BytesOut += totalOut;
                    throw new EndOfStreamException();
                }

                if (i == operations && finishing) {
                    _operationBufferOffset = _operationSize;
                    break;
                }
                iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                destination.Write(_tempBuffer, 0, iterOut);
                totalOut += iterOut;
            }

            if (finishing == false) {
                // Mid-stream
                if (remainder > 0) {
                    // Any remainder bytes are stored (not decrypted)
                    iterIn = StreamBinding.Read(_operationBuffer, _operationBufferOffset, (int)remainder);
                    totalIn += iterIn;
                    _operationBufferOffset += iterIn;
                    // End of stream detection
                    if (_operationBufferOffset < remainder) {
                        throw new EndOfStreamException();
                    }
                }
            } else {
                // Finishing
                int totalRemaining = (int)remainder + _operationBufferOffset;
                if (totalRemaining > _operationSize) {
                    int finalReadLength = _operationSize - _operationBufferOffset;
                    iterIn = StreamBinding.Read(_operationBuffer, _operationBufferOffset, finalReadLength);
                    // End of stream detection
                    if (iterIn < finalReadLength) {
                        BytesIn += totalIn;
                        BytesOut += totalOut;
                        throw new EndOfStreamException();
                    }
                    remainder -= iterIn;
                    totalIn += iterIn;
                    iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                    destination.Write(_tempBuffer, 0, iterOut);
                    totalOut += iterOut;
                    _operationBufferOffset = 0;
                }
                iterIn = StreamBinding.Read(_operationBuffer, _operationBufferOffset, (int)remainder);
                if (iterIn < remainder) {
                    BytesIn += totalIn;
                    BytesOut += totalOut;
                    throw new EndOfStreamException();
                }
                _operationBufferOffset += iterIn;
                totalIn += iterIn;
                iterOut = FinishReading(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
                destination.Write(_tempBuffer, 0, iterOut);
                totalOut += iterOut;
                _operationBufferOffset = 0;
            }

            BytesIn += totalIn;
            BytesOut += totalOut;
            return totalOut;
        }

        /// <summary>
        /// Finishes the writing/encryption operation, processing the final block/stride.
        /// </summary>
        /// <returns>Size of final block written.</returns>
        /// <exception cref="DataLengthException">Final bytes could not be written to the output.</exception>
        private void FinishWriting () {
            // Write any partial but complete block(s)
            int finalLength = _outBuffer.Length;
            _outBuffer.TakeTo(Binding, finalLength);
            BytesOut += finalLength;
            try {
                finalLength = _cipher.ProcessFinal(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
            } catch (DataLengthException dlEx) {
                if (String.Equals(dlEx.Message, "output buffer too short")) {
                    throw new DataLengthException(WritingError);
                } else {
                    throw new DataLengthException(UnknownFinaliseError, dlEx);
                }
            } catch (Exception ex) {
                //throw new Exception(UnknownFinaliseError, ex);
                throw;
            }
            // Write out the final block
            Binding.Write(_tempBuffer, 0, finalLength);
            BytesOut += finalLength;
        }

        private int FinishReading (byte[] input, int inputOffset, int length, byte[] output, int outputOffset) {
            int finalByteQuantity = _outBuffer.Length;
            _outBuffer.Take(output, outputOffset, finalByteQuantity);
            outputOffset += finalByteQuantity;
            try {
                finalByteQuantity += _cipher.ProcessFinal(input, inputOffset, length, output, outputOffset);
            } catch (Exception ex) {
                throw;
            }

            base.Finish();
            return finalByteQuantity;
        }

        /// <summary>
        /// Finish the encryption/decryption operation manually. 
        /// Unnecessary for writing, as this is done automatically when closing/disposing the stream, 
        /// with the output being writen to the StreamBinding. 
        /// When reading, can be used if it is certain that all necessary data has been read. 
        /// Output is available in this latter case from GetFinalBytes() .
        /// </summary>
        protected override void Finish () {
            if (Disposed)
                throw new ObjectDisposedException("Stream has been disposed.");
            if (Finished)
                return;

            if (Encrypting) {
                FinishWriting();
            } else if (Encrypting == false && _operationBufferOffset > 0) {
                throw new InvalidOperationException("Should never finish in this state when decrypting.");
            }
            base.Finish();
        }

        protected override void Reset (bool finish = false) {
            Array.Clear(_operationBuffer, 0, _operationBuffer.Length);
            _operationBufferOffset = 0;
            Array.Clear(_tempBuffer, 0, _tempBuffer.Length);
            _outBuffer.Reset();
            _cipher.Reset();
            base.Reset(finish);
        }
    }
}
