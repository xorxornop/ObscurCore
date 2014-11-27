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
using Obscur.Core.Cryptography.Ciphers.Block;
using Obscur.Core.Cryptography.Ciphers.Block.Padding;
using Obscur.Core.Cryptography.Ciphers.Stream;
using Obscur.Core.DTO;
using PerfCopy;
using RingByteBuffer;

namespace Obscur.Core.Cryptography.Ciphers
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

        private const string WritingExactlySourceEosError = "Insufficient data able to be supplied by source to satisfy requested write length.";
        private const string ReadingExactlyBindingEosError = "Insufficient data able to be supplied by binding to satisfy requested read length.";

        private const int StreamBufferSize = 16384;
        private const int StreamBufferIoThreshold = StreamBufferSize / 2;

        private bool _disposed = false;

        private readonly ICipherWrapper _cipher;
        private readonly int _opSize;
        private readonly int _opSize_CipherNative; // only used when finalising - determines particulars of some behaviours (e.g. block cipher padding)
        
        private readonly int _maxCipherOutputDelta;
        private bool _finalisingOnOpBoundaryRequired;   

        private System.IO.Stream _streamBinding;
        private readonly bool _closeOnDispose;

        private RingBuffer _inBuffer; // data before processing
        private RingBuffer _outBuffer; // data after processing

        private byte[] _opInBuffer; // primary buffer
        private int _opBufferOffset;       
        private byte[] _opOutBuffer; // freshly-encrypted or decrypted data
       

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
#if INCLUDE_CONTRACTS
            Contract.Requires(binding != null);
            Contract.Requires(config != null);
            Contract.Requires(key != null);
#endif

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
                    _cipher = InitBlockCipher(encrypting, config, key, out _maxCipherOutputDelta);
                    break;
                case CipherType.Stream:
                    _cipher = InitStreamCipher(encrypting, config, key, out _maxCipherOutputDelta);
                    break;
                default:
                    throw new ArgumentException("Not a valid cipher configuration.");
            }

            _opSize = _cipher.OperationSize;
            // Initialise the buffers 
            _opInBuffer = new byte[_opSize];
            _opOutBuffer = new byte[(_opSize + _maxCipherOutputDelta) * 2];
            _inBuffer = new ConcurrentRingBuffer(16384);
            _outBuffer = new ConcurrentRingBuffer(16384);

            // LSH 8 upscales (256x) : 8 (64 bits) to 2048 [2kB], 16 (128) to 4096 [4kB], 32 (256) to 8192 [8kB]
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
                if (CanSeek == false) {
                    throw new NotSupportedException("Seeking within the stream is not supported - cannot modify position.");
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
        private static ICipherWrapper InitBlockCipher(bool encrypting, CipherConfiguration config, byte[] key, out int maxDelta)
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

            maxDelta = Athena.Cryptography.BlockCiphers[blockCipherPrimitive.Identity].MaximumOutputSizeDifference(encrypting);

            blockCipher.Init(encrypting, key, blockConfigWrapper.GetInitialisationVector());
            return new BlockCipherWrapper(encrypting, blockCipher, padding);
        }

        /// <summary>
        ///     Initialises a stream cipher from cipher configuration DTO. Used by constructor.
        /// </summary>
        private static ICipherWrapper InitStreamCipher(bool encrypting, CipherConfiguration config, byte[] key, out int maxDelta)
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

            // This should always be 0, but we'll do it anyway...
            maxDelta = Athena.Cryptography.StreamCiphers[streamCipher.Identity].MaximumOutputSizeDifference(encrypting); 

            return new StreamCipherWrapper(encrypting, streamCipher, strideIncreaseFactor:2);
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
                throw new InvalidOperationException("Encryption/decryption already finished (cipher state finalised) - cannot continue to perform I/O.");
            }
        }


        /// <summary>
        ///     Finish the encryption/decryption operation manually.
        ///     Unnecessary for writing, as this is done automatically when closing/disposing the stream,
        ///     with the output being writen to the StreamBinding.
        ///     When reading, can be used if it is certain that all necessary data has been read.
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

#if INCLUDE_CONTRACTS && CONTRACTS_ASSERT
            if (Encrypting == false) {
                Contract.Assert(_opBufferOffset == 0, "Decryption finalisation in undefined state. Data remaining in buffers.");
            }
#endif
        }

        /// <summary>
        ///     Reset the internal cipher and associated state. Optionally, attempt to 
        ///     set the position of the stream <see cref="Binding"/> to a new position.
        /// </summary>
        /// <param name="resetPosition">
        ///     What position to attempt to set the current stream <see cref="Binding"/> to. 
        ///     Default is 'None' (left at current position).
        /// </param>
        public void Reset(ResetPosition resetPosition = ResetPosition.None)
        {
            _opInBuffer.SecureWipe();
            _opBufferOffset = 0;
            _opOutBuffer.SecureWipe();
            _inBuffer.Reset();
            _outBuffer.Reset();
            _cipher.Reset();

            BytesIn = 0;
            BytesOut = 0;
            Finished = false;
        }

        public enum ResetPosition
        {
            /// <summary>
            ///     Stream position is left unchanged from its current state.
            /// </summary>
            None,
            StreamStart,
            OriginalPosition
        }

        public void Reset(System.IO.Stream newBinding = null)
        {
            Reset(ResetPosition.None);
            _streamBinding = newBinding;
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

            if (_opBufferOffset < _opSize) {
                _opInBuffer[_opBufferOffset++] = b;
            } else {
                int iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
                _opBufferOffset = 0;
            }

            if (_outBuffer.CurrentLength > 0) {
                _streamBinding.WriteByte(_outBuffer.Take());
            }
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
            int gapLength = _opSize - _opBufferOffset;
            if (_opBufferOffset > 0 && count > gapLength) {
                buffer.DeepCopy_NoChecks(offset, _opInBuffer, _opBufferOffset, gapLength);
                totalIn += gapLength;
                iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _opBufferOffset = 0;
                offset += gapLength;
                count -= gapLength;
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
            }

            if (count < 0) {
                return;
            }

            while (count > _opSize) {
                iterOut = _cipher.ProcessBytes(buffer, offset, _opOutBuffer, 0);
                totalIn += _opSize;
                offset += _opSize;
                count -= _opSize;
                _outBuffer.Put(_opOutBuffer, 0, iterOut);

                // Prevent possible writebuffer overflow
                if (_outBuffer.Spare < _opSize) {
                    iterOut = _outBuffer.CurrentLength;
                    // Write out the processed data to the stream StreamBinding
                    _outBuffer.TakeTo(_streamBinding, iterOut);
                    totalOut += iterOut;
                }
            }

            // Store any remainder in operation buffer
            buffer.DeepCopy_NoChecks(offset, _opInBuffer, _opBufferOffset, count);
            totalIn += count;
            _opBufferOffset += count;

            // Write out the processed data to the stream StreamBinding
            iterOut = _outBuffer.CurrentLength - _opSize;
            if (iterOut > 0) {
                //iterOut = _outBuffer.Length; 
                _outBuffer.TakeTo(_streamBinding, iterOut);
                totalOut += iterOut;
            }
            BytesOut += totalOut;
            BytesIn += totalIn;
        }

        /// <summary>
        ///     Encrypts and writes specified quantity of bytes exactly (after cipher transform).
        /// </summary>
        /// <param name="source">Stream containing data to be encrypted and written.</param>
        /// <param name="length">Length of data to be written.</param>
        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
        public long WriteExactly(System.IO.Stream source, long length)
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
            if (_opBufferOffset > 0 && length > _opSize) {
                int gapLength = _opSize - _opBufferOffset;

                iterIn = source.Read(_opInBuffer, _opBufferOffset, gapLength);
                if (iterIn > gapLength) {
                    throw new EndOfStreamException();
                }

                totalIn += iterIn;
                iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _opBufferOffset = 0;
                length -= iterOut;
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
            }

            while (totalOut + _outBuffer.CurrentLength < length) {
                // Prevent possible writebuffer overflow
                if (_outBuffer.Spare < _opSize) {
                    iterOut = _outBuffer.CurrentLength;
                    // Write out the processed data to the stream StreamBinding
                    _outBuffer.TakeTo(Binding, iterOut);
                    totalOut += iterOut;
                }

                iterIn = source.Read(_opInBuffer, 0, _opSize);
                totalIn += iterIn;
                // We might have tried to read past the end simply because of the opsize requirement
                if (iterIn < _opSize) {
                    _opBufferOffset = iterIn;
                    int finalLength = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
                    _outBuffer.Put(_opOutBuffer, 0, finalLength);
                    break;
                }
                iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
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







//        /// <summary>
//        ///     Asynchronously encrypts and writes specified quantity of 
//        ///     bytes exactly (after cipher transform) to the <see cref="Binding"/> 
//        ///     such that <see cref="T:Binding.Position"/> position <c>p</c> will be <c>p + length</c> 
//        ///     after finishing. 
//        /// </summary>
//        /// <remarks>
//        ///     May have higher performance than <see cref="WriteExactly"/> due to 
//        ///     implementation of concurrent stream buffer I/O and enciphering. 
//        ///     Input from <paramref name="source"/> can be read into the input buffer 
//        ///     at the same time it is also taken from that same buffer for encryption - 
//        ///     as is the case for output.
//        /// </remarks>
//        /// <param name="source">Stream containing data to be encrypted and written.</param>
//        /// <param name="length">Length of data to be written.</param>
//        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
//        public async Task<long> WriteExactlyAsync(System.IO.Stream source, long length)
//        {
//#if INCLUDE_CONTRACTS
//            Contract.Requires(source != null);
//            Contract.Requires(length >= 0);
//#else
//            if (source == null) {
//                throw new ArgumentNullException("source");
//            }
//            if (length < 0) {
//                throw new ArgumentException("length");
//            }
//#endif

//            CheckIfCanDecorate();
//            if (Writing == false) {
//                throw new InvalidOperationException(NotWritingError);
//            }         

//            int totalIn = 0, totalOut = 0;
//            int iterIn, iterOut;

//            // Process any remainder
//            if (_opBufferOffset > 0 && length > _opSize) {
//                int gapLength = _opSize - _opBufferOffset;

//                iterIn = await source.ReadAsync(_opInBuffer, _opBufferOffset, gapLength);
//                if (iterIn > gapLength) {
//                    throw new EndOfStreamException();
//                }

//                totalIn += iterIn;
//                iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
//                _opBufferOffset = 0;
//                length -= iterOut;
//                _outBuffer.Put(_opOutBuffer, 0, iterOut);
//            }

//            int streamInReadRequest = StreamBufferSize - _inBuffer.CurrentLength;
//            Task<int> streamInReadTask = _inBuffer.PutFromAsync(source, streamInReadRequest, CancellationToken.None);
//            Task streamOutWriteTask = null;

//            bool endOfStreamIn = false;

//            while (totalOut + _outBuffer.CurrentLength < length) {

//                _inBuffer.Take(_opInBuffer);

//                // Prevent possible inbuffer underrun (proactively)
//                if (_inBuffer.CurrentLength <= StreamBufferIoThreshold) {
//                    if (_inBuffer.CurrentLength < _opSize) {
//                        Debug.Assert(streamInReadTask != null);
//                        // Cannot proceed until task completes!
//                        var streamInReturn = await streamInReadTask;
//                        if (streamInReturn < streamInReadRequest) {
//                            // EOS
//                            var operationsRemaining = (double)_inBuffer.CurrentLength / _opSize_CipherNative;
//                            if (_finalisingOnOpBoundaryRequired) 
//                                operationsRemaining = Math.Ceiling(operationsRemaining);
//                            int requiredLength = (int)operationsRemaining * _opSize_CipherNative;
//                            if (streamInReturn < requiredLength) {
//                                throw new EndOfStreamException(WritingExactlySourceEosError);
//                            }
//                        }
//                    } else if (streamInReadTask.IsCompleted) {

//                    } else if (streamInReadTask == null || streamInReadTask.IsCompleted) {
//                        int streamInSpare = StreamBufferSize - _inBuffer.CurrentLength;
//                        streamInReadRequest = Math.Min((int)length, streamInSpare);
//                        streamInReadTask = _inBuffer.PutFromAsync(source, streamInReadRequest, CancellationToken.None);
//                    }
//                }
//                // Prevent possible outbuffer overflow (proactively)
//                if (_outBuffer.CurrentLength >= StreamBufferIoThreshold) {
//                    if (_inBuffer.CurrentLength + _opSize < StreamBufferSize) {
//                        Debug.Assert(streamOutWriteTask != null);
//                        // Cannot proceed until task completes!
//                        await streamOutWriteTask;
//                    } else if (streamOutWriteTask == null) {
//                        var streamOutRequest = _outBuffer.CurrentLength;
//                        streamOutWriteTask = _outBuffer.TakeToAsync(Binding, streamOutRequest, CancellationToken.None);
//                        totalOut += streamOutRequest;
//                    }
//                }

                
//                totalIn += iterIn;
//                // We might have tried to read past the end simply because of the opsize requirement
//                if (iterIn < _opSize) {
//                    _opBufferOffset = iterIn;
//                    int finalLength = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
//                    _outBuffer.Put(_opOutBuffer, 0, finalLength);
//                    break;
//                }
//                iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
//                _outBuffer.Put(_opOutBuffer, 0, iterOut);
//            }

//            // Write out the processed data to the stream StreamBinding
//            iterOut = (int)(length - totalOut);
//            if (iterOut > 0) {
//                _outBuffer.TakeTo(Binding, iterOut);
//                totalOut += iterOut;
//            }

//            BytesOut += totalOut;
//            BytesIn += totalIn;

//            return totalIn;
//        }









        

        

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
                finalLength = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
            } catch (DataLengthException dlEx) {
                if (String.Equals(dlEx.Message, "output buffer too short")) {
                    throw new DataLengthException(WritingError);
                }
                throw new DataLengthException(UnknownFinaliseError, dlEx);
            } catch (Exception e) {
                throw new CryptoException("Unexpected error on cipher finalising operation while writing.", e);
            }
            // Write out the final block
            Binding.Write(_opOutBuffer, 0, finalLength);
            BytesOut += finalLength;
        }

        #endregion

        #region Reading (decryption)

        public override int ReadByte()
        {
            if (_disposed) {
                throw new ObjectDisposedException("Stream has been disposed.");
            }
            
            if (Writing) {
                throw new InvalidOperationException(NotReadingError);
            }

            if (Finished && _outBuffer.CurrentLength == 0) {
                return -1;
            }

            if (_outBuffer.CurrentLength == 0) {
                int toRead = _opSize - _opBufferOffset;
                int iterIn = _streamBinding.Read(_opInBuffer, 0, toRead);
                BytesIn += iterIn;
                _opBufferOffset += iterIn;
                if (iterIn == 0) {
                    int iterOut = FinishReading(_opOutBuffer, 0);
                    _opBufferOffset = 0;
                    _outBuffer.Put(_opOutBuffer, 0, iterOut);
                    BytesOut++;
                    return _outBuffer.Take();
                }
            }

            if (_opBufferOffset == _opSize) {
                // Op buffer is full, process an op block
                int iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
                _opBufferOffset = 0;
            }

            return _outBuffer.Take();
        }

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
                    int iterIn = _streamBinding.Read(_opInBuffer, _opBufferOffset,
                        _opSize - _opBufferOffset);
                    if (iterIn > 0) {
                        // Normal processing (mid-stream)
                        _opBufferOffset += iterIn;
                        totalIn += iterIn;
                        if (_opBufferOffset != _opSize) {
                            continue;
                        }
                        if (count >= _opSize) {
                            // Full operation
                            iterOut = _cipher.ProcessBytes(_opInBuffer, 0, buffer, offset);
                            totalOut += iterOut;
                            offset += iterOut;
                            count -= iterOut;
                        } else {
                            // Short operation
                            iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                            int subOp = buffer.Length - offset;
                            _opOutBuffer.DeepCopy_NoChecks(0, buffer, offset, subOp);
                            totalOut += subOp;
                            _outBuffer.Put(_opOutBuffer, count, iterOut - subOp);
                            count = 0;
                        }
                        _opBufferOffset = 0;
                    } else {
                        // End of stream - finish the decryption
                        // Copy the previous operation block in to provide overrun protection
                        buffer.DeepCopy_NoChecks(offset - _opSize, _opOutBuffer, 0, _opSize);
                        iterOut = FinishReading(_opOutBuffer, _opSize);
                        if (iterOut > 0) {
                            // Process the final decrypted data
                            int remainingBufferSpace = buffer.Length - (offset + iterOut);
                            if (remainingBufferSpace < 0) {
                                // Not enough space in destination buffer
                                int subOp = buffer.Length - offset;
                                _opOutBuffer.DeepCopy_NoChecks(_opSize, buffer, offset, subOp);
                                totalOut += subOp;
                                _outBuffer.Put(_opOutBuffer, _opSize + subOp, iterOut - subOp);
                            } else {
                                _opOutBuffer.DeepCopy_NoChecks(_opSize, buffer, offset, iterOut);
                                totalOut += iterOut;
                            }
                        } else {
                            // We need to modify the existing output because the last block was actually padded!
                            totalOut += iterOut; // iterOut is negative, so this is actually negation
                        }
                        count = 0;
                        _opBufferOffset = 0;
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
        public long ReadExactly(System.IO.Stream destination, long length, bool finishing = false)
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
                int opSize = _opSize - _opBufferOffset;
                if (opSize > remaining) {
                    opSize = (int) remaining;
                }
                iterIn = _streamBinding.Read(_opInBuffer, _opBufferOffset, opSize);
                _opBufferOffset += iterIn;
                totalIn += iterIn;
                //				length -= iterIn;
                if ((finishing && remaining <= _opSize) || iterIn == 0) {
                    // Finish the decryption - end of stream
                    iterOut = FinishReading(_opOutBuffer, 0);
                    destination.Write(_opOutBuffer, 0, iterOut);
                    totalOut += iterOut;
                    _opBufferOffset = 0;
                } else if (_opBufferOffset == _opSize) {
                    // Normal processing (mid-stream)
                    iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                    destination.Write(_opOutBuffer, 0, iterOut);
                    totalOut += iterOut;
                    _opBufferOffset = 0;
                }
            }

            BytesIn += totalIn;
            BytesOut += totalOut;
            return totalOut;
        }

        

        private int FinishReading(byte[] output, int outputOffset)
        {
            int finalByteQuantity = _outBuffer.CurrentLength;
            _outBuffer.Take(output, outputOffset, finalByteQuantity);
            outputOffset += finalByteQuantity;
            try {
                finalByteQuantity += _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, output, outputOffset);
                _opBufferOffset = 0;
            } catch (Exception e) {
                throw new CipherException("Unexpected error when finalising (reading). Inner exception may have additional information.", e);
            }

            Finish();
            return finalByteQuantity;
        }

        #endregion
    }

    internal class CipherRingBuffer : SequentialRingBuffer
    {
        public CipherRingBuffer(int maximumCapacity, byte[] buffer = null, bool allowOverwrite = false)
            : base(maximumCapacity, buffer, allowOverwrite) {}
    }
}
