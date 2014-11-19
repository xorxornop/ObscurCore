#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using System.Diagnostics.Contracts;
using System.IO;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;
using PerfCopy;
using RingByteBuffer;

namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    ///     Decorating stream implementing encryption/decryption operations by a symmetric cipher.
    /// </summary>
    public sealed class CipherStream : System.IO.Stream, IStreamDecorator
    {
        private const string UnknownFinaliseError =
            "An unknown type of error occured while transforming the final block of ciphertext.";

        private const string WritingError =
            "Could not write transformed block bytes to output stream.";

        private const string NotWritingError =
            "Stream is configured for encryption, and so may only be written to.";

        private const string NotReadingError =
            "Stream is configured for decryption, and so may only be read from.";

        private readonly ICipherWrapper _cipher;

        private readonly bool _closeOnDispose;
        private readonly int _operationSize;

        private System.IO.Stream _streamBinding;
        private bool _disposed = false;

        private RingBuffer _inBuffer; // data before processing

        private byte[] _operationBuffer; // primary buffer
        private int _operationBufferOffset;
        private RingBuffer _outBuffer; // data after processing
        private byte[] _tempBuffer;

        /// <summary>
        ///     Initialises the stream and its associated cipher for operation automatically from provided configuration
        ///     object.
        /// </summary>
        /// <param name="binding">Stream to be written/read to/from.</param>
        /// <param name="encrypting">Specifies whether the stream is for writing (encrypting) or reading (decryption).</param>
        /// <param name="config">Configuration object describing how to set up the internal cipher and associated services.</param>
        /// <param name="key">Derived cryptographic key for the internal cipher to operate with.</param>
        /// <param name="closeOnDispose">Set to <c>true</c> to also close the base stream when closing, or vice-versa.</param>
        public CipherStream(System.IO.Stream binding, bool encrypting, CipherConfiguration config, byte[] key,
                            bool closeOnDispose)
        {
            Contract.Requires(binding != null);
            Contract.Requires(config != null);

            if (key.IsNullOrZeroLength()) {
                throw new ArgumentException("No key provided.", "key");
            }

            Writing = encrypting;
            _streamBinding = binding;
            _closeOnDispose = closeOnDispose;

            switch (config.Type) {
                case CipherType.None:
                    throw new ConfigurationInvalidException(
                        "Cipher type is never set to None in a valid cipher configuration.");
                case CipherType.Block:
                    _cipher = InitBlockCipher(encrypting, config, key);
                    break;
                case CipherType.Stream:
                    _cipher = InitStreamCipher(encrypting, config, key);
                    break;
                default:
                    throw new ArgumentException("Not a valid cipher configuration.");
            }

            // Initialise the buffers 
            _operationSize = _cipher.OperationSize;
            _operationBuffer = new byte[_operationSize];
            _tempBuffer = new byte[_operationSize * 2];
            _outBuffer = new SequentialRingBuffer(_cipher.OperationSize << (encrypting ? 8 : 2));
            // Shift left 8 upscales : 8 (64 bits) to 2048 [2kB], 16 (128) to 4096 [4kB], 32 (256) to 8192 [8kB]
        }

        public bool Finished { get; private set; }

        internal int OutputBufferSize 
        {
            get { return _outBuffer.MaximumCapacity; }
        }

        /// <summary>
        ///     What mode is active - encryption or decryption?
        /// </summary>
        public bool Encrypting
        {
            get { return Writing; }
        }

        public override bool CanRead
        {
            get { return !Writing && _streamBinding.CanRead; }
        }

        public override bool CanWrite
        {
            get { return Writing && _streamBinding.CanWrite; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override long Length
        {
            get { return _streamBinding.Length; }
        }

        public override long Position
        {
            get { return Binding.Position; }
            set
            {
                if (!CanSeek) {
                    throw new NotSupportedException();
                }
                //StreamBinding.Position = value;
                _streamBinding.Seek(value, SeekOrigin.Begin);
            }
        }

        #region IStreamDecorator Members

        /// <summary>
        ///     Stream that decorator writes to or reads from.
        /// </summary>
        public System.IO.Stream Binding
        {
            get { return _streamBinding; }
        }

        public bool Writing { get; private set; }

        public long BytesIn { get; private set; }

        public long BytesOut { get; private set; }

        #endregion

        /// <summary>
        ///     Initialises a block cipher from cipher configuration DTO. Used by constructor.
        /// </summary>
        private static ICipherWrapper InitBlockCipher(bool encrypting, CipherConfiguration config, byte[] key)
        {
            var blockConfigWrapper = new BlockCipherConfigurationWrapper(config);
            if (key.Length != blockConfigWrapper.KeySizeBytes) {
                throw new ArgumentException("Key is not of the length declared in the cipher configuration.",
                    "key");
            }

            BlockCipherBase blockCipherPrimitive = CipherFactory.CreateBlockCipher(blockConfigWrapper.GetBlockCipher(),
                blockConfigWrapper.GetBlockSizeBits());
            // Overlay the cipher with the mode of operation
            BlockCipherModeBase blockCipher;
            try {
                blockCipher = CipherFactory.OverlayBlockCipherWithMode(blockCipherPrimitive, blockConfigWrapper.Mode);
            } catch (Exception e) {
                throw new ConfigurationInvalidException(
                    "Configuration of block cipher mode of operation is invalid.", e.InnerException);
            }
            IBlockCipherPadding padding = null;
            BlockCipherPadding paddingEnum = blockConfigWrapper.GetPadding();
            if (paddingEnum != BlockCipherPadding.None) {
                padding = CipherFactory.CreatePadding(paddingEnum);
                padding.Init(StratCom.EntropySupplier);
            }
            blockCipher.Init(encrypting, key, blockConfigWrapper.GetInitialisationVector());
            return new BlockCipherWrapper(encrypting, blockCipher, padding);
        }

        /// <summary>
        ///     Initialises a stream cipher from cipher configuration DTO. Used by constructor.
        /// </summary>
        private static ICipherWrapper InitStreamCipher(bool encrypting, CipherConfiguration config, byte[] key)
        {
            var streamConfigWrapper = new StreamCipherConfigurationWrapper(config);
            if (key.Length != streamConfigWrapper.KeySizeBytes) {
                throw new ArgumentException("Key is not of the length declared in the cipher configuration.",
                    "key");
            }

            StreamCipherEngine streamCipher;
            try {
                streamCipher = CipherFactory.CreateStreamCipher(streamConfigWrapper.GetStreamCipher());
                streamCipher.Init(encrypting, key, streamConfigWrapper.GetNonce());
            } catch (Exception e) {
                throw new ConfigurationInvalidException("Configuration of stream cipher is invalid.",
                    e.InnerException);
            }
            return new StreamCipherWrapper(encrypting, streamCipher, 2);
        }

        /// <summary>
        ///     When encrypting/writing, causes any buffered output data to be written to the <see cref="Binding" />.
        ///     <see cref="Binding" /> will have its respective Flush() method called.
        /// </summary>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs.</exception>
        public override void Flush()
        {
            if (Writing) {
                _outBuffer.TakeTo(Binding, _outBuffer.CurrentLength);
            }
            _streamBinding.Flush();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!CanSeek) {
                throw new NotSupportedException();
            }
            return _streamBinding.Seek(offset, origin);
        }

        /// <summary>
        ///     When overridden in a derived class, sets the length of the current stream.
        /// </summary>
        /// <param name="value">The desired length of the current stream in bytes.</param>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs.</exception>
        /// <exception cref="T:System.NotSupportedException">
        ///     The stream does not support both writing and seeking, such as if the stream is constructed from a pipe or console
        ///     output.
        /// </exception>
        /// <exception cref="T:System.ObjectDisposedException">Methods were called after the stream was closed.</exception>
        public override void SetLength(long value)
        {
            if (Writing) {
                if (value < BytesOut) {
                    throw new ArgumentException();
                }
                Binding.SetLength(value);
            } else {
                if (value < BytesIn) {
                    throw new ArgumentException();
                }
                Binding.SetLength(value);
            }
        }

        /// <summary>
        ///     Check if disposed or finished (throw exception if either).
        /// </summary>
        private void CheckIfCanDecorate()
        {
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Finished) {
                throw new InvalidOperationException();
            }
        }


        /// <summary>
        ///     Finish the encryption/decryption operation manually.
        ///     Unnecessary for writing, as this is done automatically when closing/disposing the stream,
        ///     with the output being writen to the StreamBinding.
        ///     When reading, can be used if it is certain that all necessary data has been read.
        ///     Output is available in this latter case from GetFinalBytes() .
        /// </summary>
        private void Finish()
        {
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            } else if (Finished) {
                return;
            }

            if (Encrypting) {
                FinishWriting();
            }
            Finished = true;

            if (Encrypting == false) {
                Contract.Assert(_operationBufferOffset == 0, "Decryption finalisation in undefined state. Data remaining in buffers.");
            }
        }

        /// <summary>
        ///     Finishes the writing/encryption operation, processing the final block/stride.
        /// </summary>
        /// <returns>Size of final block written.</returns>
        /// <exception cref="DataLengthException">Final bytes could not be written to the output.</exception>
        private void FinishWriting()
        {
            // Write any partial but complete block(s)
            int finalLength = _outBuffer.CurrentLength;
            _outBuffer.TakeTo(Binding, finalLength);
            BytesOut += finalLength;
            try {
                finalLength = _cipher.ProcessFinal(_operationBuffer, 0, _operationBufferOffset, _tempBuffer, 0);
            } catch (DataLengthException dlEx) {
                if (String.Equals(dlEx.Message, "output buffer too short")) {
                    throw new DataLengthException(WritingError);
                }
                throw new DataLengthException(UnknownFinaliseError, dlEx);
            } catch (Exception e) {
                throw new CryptoException("Unexpected error on cipher finalising operation while writing.", e);
            }
            // Write out the final block
            Binding.Write(_tempBuffer, 0, finalLength);
            BytesOut += finalLength;
        }

        private int FinishReading(byte[] output, int outputOffset)
        {
            int finalByteQuantity = _outBuffer.CurrentLength;
            _outBuffer.Take(output, outputOffset, finalByteQuantity);
            outputOffset += finalByteQuantity;
            try {
                finalByteQuantity += _cipher.ProcessFinal(_operationBuffer, 0, _operationBufferOffset, output, outputOffset);
                _operationBufferOffset = 0;
            } catch (Exception e) {
                throw new CipherException("Unexpected error when finalising (reading). Inner exception may have additional information.", e);
            }

            Finish();
            return finalByteQuantity;
        }

        public void Reset()
        {
            _operationBuffer.SecureWipe();
            _operationBufferOffset = 0;
            _tempBuffer.SecureWipe();
            _outBuffer.Reset();
            _cipher.Reset();

            BytesIn = 0;
            BytesOut = 0;
            Finished = false;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) {
                // dispose managed resources
                Finish();
                if (_streamBinding != null && _closeOnDispose) {
                    _streamBinding.Close();
                }
                _streamBinding = null;
            }
        }

        #region Writing (encryption)

        /// <summary>
        ///     Encrypts and writes specified quantity of bytes exactly (after cipher transform).
        /// </summary>
        /// <param name="source">Stream containing data to be encrypted and written.</param>
        /// <param name="length">Length of data to be written.</param>
        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
        public long WriteExactlyFrom(System.IO.Stream source, long length)
        {
            CheckIfCanDecorate();
            if (Writing == false) {
                throw new InvalidOperationException(NotWritingError);
            }
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

            while (totalOut + _outBuffer.CurrentLength < length) {
                // Prevent possible writebuffer overflow
                if (_outBuffer.Spare < _operationSize) {
                    iterOut = _outBuffer.CurrentLength;
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
            iterOut = (int) (length - totalOut);
            if (iterOut > 0) {
                _outBuffer.TakeTo(Binding, iterOut);
                totalOut += iterOut;
            }

            BytesOut += totalOut;
            BytesIn += totalIn;

            return totalIn;
        }


        public override void Write(byte[] buffer, int offset, int count)
        {
            CheckIfCanDecorate();
            if (!Writing) {
                throw new InvalidOperationException(NotWritingError);
            }
            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            }
            if (buffer.Length < offset + count) {
                throw new DataLengthException();
            }

            int totalIn = 0, totalOut = 0;
            int iterOut = 0;

            // Process any leftovers
            int gapLength = _operationSize - _operationBufferOffset;
            if (_operationBufferOffset > 0 && count > gapLength) {
                buffer.DeepCopy_NoChecks(offset, _operationBuffer, _operationBufferOffset, gapLength);
                totalIn += gapLength;
                iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                _operationBufferOffset = 0;
                offset += gapLength;
                count -= gapLength;
                _outBuffer.Put(_tempBuffer, 0, iterOut);
            }

            if (count < 0) {
                return;
            }

            while (count > _operationSize) {
                iterOut = _cipher.ProcessBytes(buffer, offset, _tempBuffer, 0);
                totalIn += _operationSize;
                offset += _operationSize;
                count -= _operationSize;
                _outBuffer.Put(_tempBuffer, 0, iterOut);

                // Prevent possible writebuffer overflow
                if (_outBuffer.Spare < _operationSize) {
                    iterOut = _outBuffer.CurrentLength;
                    // Write out the processed data to the stream StreamBinding
                    _outBuffer.TakeTo(_streamBinding, iterOut);
                    totalOut += iterOut;
                }
            }

            // Store any remainder in operation buffer
            buffer.DeepCopy_NoChecks(offset, _operationBuffer, _operationBufferOffset, count);
            totalIn += count;
            _operationBufferOffset += count;

            // Write out the processed data to the stream StreamBinding
            iterOut = _outBuffer.CurrentLength - _operationSize;
            if (iterOut > 0) {
                //iterOut = _outBuffer.Length; 
                _outBuffer.TakeTo(_streamBinding, iterOut);
                totalOut += iterOut;
            }
            BytesOut += totalOut;
            BytesIn += totalIn;
        }

        /// <summary>
        ///     Encrypts and writes a byte. Not guaranteed or even likely to be written out immediately.
        ///     If writing precision is required, do not use this wherever possible.
        /// </summary>
        /// <param name="b">Byte to encrypt and write.</param>
        public override void WriteByte(byte b)
        {
            CheckIfCanDecorate();
            if (Writing == false) {
                throw new InvalidOperationException(NotWritingError);
            }

            if (_operationBufferOffset < _operationSize) {
                _operationBuffer[_operationBufferOffset++] = b;
            } else {
                int iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                _outBuffer.Put(_tempBuffer, 0, iterOut);
                _operationBufferOffset = 0;
            }

            if (_outBuffer.CurrentLength > 0) {
                _streamBinding.WriteByte(_outBuffer.Take());
            }
        }

        #endregion

        #region Reading (decryption)

        /// <summary>
        ///     Read and decrypt bytes from the stream StreamBinding into the supplied array.
        ///     Not guaranteed to read 'count' bytes if ReadByte() has been used.
        ///     Guaranteed to return 'count' bytes until end of stream.
        /// </summary>
        /// <returns>Quantity of bytes read into supplied buffer array.</returns>
        /// <param name="buffer">Buffer.</param>
        /// <param name="offset">Offset.</param>
        /// <param name="count">Count.</param>
        /// <exception cref="InvalidOperationException">Stream is encrypting, not decrypting.</exception>
        /// <exception cref="ArgumentNullException">Destination stream is null.</exception>
        /// <exception cref="DataLengthException">Array insufficient size to accept decrypted data.</exception>
        /// <exception cref="EndOfStreamException">Required quantity of bytes could not be read.</exception>
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_disposed) {
                throw new ObjectDisposedException("Stream has been disposed.");
            }
            if (Finished && _outBuffer.CurrentLength == 0) {
                return 0;
            }
            if (Writing) {
                throw new InvalidOperationException(NotReadingError);
            }
            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            }
            if (buffer.Length < offset + count) {
                throw new DataLengthException();
            }

            int totalIn = 0, totalOut = 0;
            int iterOut;

            if (_outBuffer.CurrentLength > 0) {
                iterOut = Math.Min(_outBuffer.CurrentLength, count);
                _outBuffer.Take(buffer, offset, iterOut);
                totalOut += iterOut;
                offset += iterOut;
                count -= iterOut;
            }

            if (Finished == false) {
                while (count > 0) {
                    int iterIn = _streamBinding.Read(_operationBuffer, _operationBufferOffset,
                        _operationSize - _operationBufferOffset);
                    if (iterIn > 0) {
                        // Normal processing (mid-stream)
                        _operationBufferOffset += iterIn;
                        totalIn += iterIn;
                        if (_operationBufferOffset != _operationSize) {
                            continue;
                        }
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
                            _tempBuffer.DeepCopy_NoChecks(0, buffer, offset, subOp);
                            totalOut += subOp;
                            _outBuffer.Put(_tempBuffer, count, iterOut - subOp);
                            count = 0;
                        }
                        _operationBufferOffset = 0;
                    } else {
                        // End of stream - finish the decryption
                        // Copy the previous operation block in to provide overrun protection
                        buffer.DeepCopy_NoChecks(offset - _operationSize, _tempBuffer, 0, _operationSize);
                        iterOut = FinishReading(_tempBuffer, _operationSize);
                        if (iterOut > 0) {
                            // Process the final decrypted data
                            int remainingBufferSpace = buffer.Length - (offset + iterOut);
                            if (remainingBufferSpace < 0) {
                                // Not enough space in destination buffer
                                int subOp = buffer.Length - offset;
                                _tempBuffer.DeepCopy_NoChecks(_operationSize, buffer, offset, subOp);
                                totalOut += subOp;
                                _outBuffer.Put(_tempBuffer, _operationSize + subOp, iterOut - subOp);
                            } else {
                                _tempBuffer.DeepCopy_NoChecks(_operationSize, buffer, offset, iterOut);
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


        /// <summary>
        ///     Decrypt an exact amount of bytes from the stream <see cref="Binding" /> and write them
        ///     to a destination stream.
        /// </summary>
        /// <returns>The quantity of bytes written to the destination stream.</returns>
        /// <param name="destination">Stream to write decrypted data to.</param>
        /// <param name="length">Quantity of bytes to read.</param>
        /// <param name="finishing">
        ///     If set to <c>true</c>, final ciphertext position is located at end of requested length.
        /// </param>
        /// <exception cref="InvalidOperationException">Stream is encrypting, not decrypting.</exception>
        /// <exception cref="ArgumentNullException">Destination stream is null.</exception>
        /// <exception cref="ArgumentException">Length supplied is negative.</exception>
        /// <exception cref="EndOfStreamException">Required quantity of bytes could not be read.</exception>
        public long ReadExactlyTo(System.IO.Stream destination, long length, bool finishing = false)
        {
            CheckIfCanDecorate();
            if (Writing) {
                throw new InvalidOperationException(NotReadingError);
            }
            if (destination == null) {
                throw new ArgumentNullException("destination");
            }
            if (length < 0) {
                throw new ArgumentException("Length must be positive.", "length");
            }

            int totalIn = 0, totalOut = 0;
            int iterIn, iterOut;

            // Has ReadByte been used? If it has then we need to return the partial block
            if (_outBuffer.CurrentLength > 0) {
                iterOut = _outBuffer.CurrentLength;
                _outBuffer.TakeTo(destination, iterOut);
                totalOut += iterOut;
            }

            while (totalIn < length) {
                long remaining = length - totalIn;
                int opSize = _operationSize - _operationBufferOffset;
                if (opSize > remaining) {
                    opSize = (int) remaining;
                }
                iterIn = _streamBinding.Read(_operationBuffer, _operationBufferOffset, opSize);
                _operationBufferOffset += iterIn;
                totalIn += iterIn;
                //				length -= iterIn;
                if ((finishing && remaining <= _operationSize) || iterIn == 0) {
                    // Finish the decryption - end of stream
                    iterOut = FinishReading(_tempBuffer, 0);
                    destination.Write(_tempBuffer, 0, iterOut);
                    totalOut += iterOut;
                    _operationBufferOffset = 0;
                } else if (_operationBufferOffset == _operationSize) {
                    // Normal processing (mid-stream)
                    iterOut = _cipher.ProcessBytes(_operationBuffer, 0, _tempBuffer, 0);
                    destination.Write(_tempBuffer, 0, iterOut);
                    totalOut += iterOut;
                    _operationBufferOffset = 0;
                }
            }

            BytesIn += totalIn;
            BytesOut += totalOut;
            return totalOut;
        }

        public override int ReadByte()
        {
            if (_disposed) {
                throw new ObjectDisposedException("Stream has been disposed.");
            }
            if (Finished && _outBuffer.CurrentLength == 0) {
                return -1;
            }
            if (Writing) {
                throw new InvalidOperationException(NotReadingError);
            }

            if (_outBuffer.CurrentLength == 0) {
                int toRead = _operationSize - _operationBufferOffset;
                int iterIn = _streamBinding.Read(_operationBuffer, 0, toRead);
                BytesIn += iterIn;
                _operationBufferOffset += iterIn;
                if (iterIn == 0) {
                    int iterOut = FinishReading(_tempBuffer, 0);
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

        #endregion
    }

    internal class CipherRingBuffer : SequentialRingBuffer
    {
        public CipherRingBuffer(int maximumCapacity, byte[] buffer = null, bool allowOverwrite = false)
            : base(maximumCapacity, buffer, allowOverwrite) {}
    }
}
