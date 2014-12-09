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
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
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

        private const int StreamBufferSize = 16384; // 16 KB
        private const int StreamBufferIoThreshold = StreamBufferSize / 2; // 8 KB

        private bool _disposed = false;

        private readonly ICipherWrapper _cipher;
        private readonly int _opSize;
        private readonly int _opSize_CipherNative; // only used when finalising - determines particulars of some behaviours (e.g. block cipher padding)
        
        private readonly int _maxCipherOutputDelta;
        private readonly int _maxOperationOutputDelta;
        private bool _finalisingOnOpBoundaryRequired;   

        private System.IO.Stream _streamBinding;
        private readonly bool _closeOnDispose;

        private RingBuffer _inBuffer; // data before processing
        private RingBuffer _outBuffer; // data after processing

        private byte[] _opInBuffer; // primary buffer
        private int _opBufferOffset;       
        private byte[] _opOutBuffer; // freshly-encrypted or decrypted data


        #region Constructor and utility subroutines

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
                    _cipher = InitStreamCipher(encrypting, config, key, out _maxOperationOutputDelta, out _maxCipherOutputDelta);
                    break;
                default:
                    throw new ArgumentException("Not a valid cipher configuration.");
            }

            _opSize = _cipher.OperationSize;
            // Initialise the buffers 
            _opInBuffer = new byte[_opSize];
            _opOutBuffer = new byte[(_opSize + _maxOperationOutputDelta) * 2];
            _inBuffer = new ConcurrentRingBuffer(StreamBufferSize);
            _outBuffer = new ConcurrentRingBuffer(StreamBufferSize);

            // LSH 8 upscales (256x) : 8 (64 bits) to 2048 [2kB], 16 (128) to 4096 [4kB], 32 (256) to 8192 [8kB]
        }

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
        private static ICipherWrapper InitStreamCipher(bool encrypting, CipherConfiguration config, byte[] key, out int maxOperationDelta, out int maxCipherDelta)
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

            const int strideIncreaseFactor = 2;

            // This should always be 0, but we'll do it anyway...
            maxCipherDelta = Athena.Cryptography.StreamCiphers[streamCipher.Identity].MaximumOutputSizeDifference(encrypting);
            maxOperationDelta = maxCipherDelta << strideIncreaseFactor;

            return new StreamCipherWrapper(encrypting, streamCipher, strideIncreaseFactor);
        }

        #endregion


        #region Properties

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
            get { return Writing == false && _streamBinding.CanRead; }
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


        #region Derived Stream minor method implementations

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

        #endregion

        


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
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Finished) {
                throw new InvalidOperationException("Encryption/decryption already finished (cipher state finalised) - cannot continue to perform I/O.");
            }
            if (Writing == false) {
                throw new InvalidOperationException(NotWritingError);
            }

            if (_inBuffer.CurrentLength > 0) {
                _opInBuffer[_opBufferOffset++] = _inBuffer.Take();
                int storedInput = _inBuffer.CurrentLength;
                int readFromInput = Math.Min(_opSize, storedInput);
                _inBuffer.Take(_opInBuffer, _opBufferOffset, readFromInput);
                _opBufferOffset = _opSize;
                _inBuffer.Put(b);
            } else {
                _opInBuffer[_opBufferOffset++] = b;
            }

            if (_opBufferOffset == _opSize) {
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
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Finished) {
                throw new InvalidOperationException("Encryption/decryption already finished (cipher state finalised) - cannot continue to perform I/O.");
            }
            if (Writing == false) {
                throw new InvalidOperationException(NotWritingError);
            }
            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            }
            if (buffer.Length < offset + count) {
                throw new DataLengthException();
            }

            int totalIn = 0, totalOut = 0;

            if (_outBuffer.CurrentLength > 0) {
                int writeProcessed = Math.Min(_outBuffer.CurrentLength, count);
                _outBuffer.Take(buffer, offset, writeProcessed);
                totalOut += writeProcessed;
                offset += writeProcessed;
                count -= writeProcessed;
            }

            if (count < 1) {
                return;
            }

            while (count > 0) {
                int operationRemainder = _opSize - _opBufferOffset;
                // Process any remainder
                if (operationRemainder > 0 || _inBuffer.CurrentLength > 0) {
                    int remainderFromInBuffer = _inBuffer.CurrentLength;
                    // Fill remainder of operation buffer from '_inBuffer' ringbuffer
                    if (remainderFromInBuffer > 0) {
                        int takeFromInBuffer = Math.Min(operationRemainder, remainderFromInBuffer);
                        _inBuffer.Take(_opInBuffer, 0, takeFromInBuffer);
                        operationRemainder -= takeFromInBuffer;
                        _opBufferOffset += takeFromInBuffer;
                    }
                    // Fill remainder of operation buffer from 'buffer' array (supplied as method argument)
                    int takeFromArray = Math.Min(count, operationRemainder);
                    buffer.CopyBytes_NoChecks(offset, _opInBuffer, _opBufferOffset, takeFromArray);
                    _opBufferOffset += takeFromArray;
                    offset += takeFromArray;
                    count -= takeFromArray;
                    totalIn += _opSize;

                    if (_opBufferOffset == _opSize) {
                        int processedOutCompoundSource = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                        _opBufferOffset = 0;
                        _outBuffer.Put(_opOutBuffer, 0, processedOutCompoundSource);
                    }
                    // Any remainder is left stored in operation buffer (implicitly)
                } else {
                    int processedOutArraySource = _cipher.ProcessBytes(buffer, offset, _opOutBuffer, 0);
                    offset += _opSize;
                    count -= _opSize;
                    totalIn += _opSize;
                    _outBuffer.Put(_opOutBuffer, 0, processedOutArraySource);
                }

                // Prevent possible outbuffer overflow
                if (_outBuffer.Spare < _opSize) {
                    int overflowOut = _outBuffer.CurrentLength;
                    // Write out the processed data to the stream Binding
                    _outBuffer.TakeTo(_streamBinding, overflowOut);
                    totalOut += overflowOut;
                }
            }      

            // Write out the processed data to the stream Binding
            int writeOut = _outBuffer.CurrentLength - _opSize;
            if (writeOut > 0) {
                _outBuffer.TakeTo(_streamBinding, writeOut);
                totalOut += writeOut;
            }
            BytesOut += totalOut;
            BytesIn += totalIn;
        }

        /// <summary>
        ///     Encrypts and writes specified quantity of bytes exactly (after cipher transform), 
        ///     synchronously.
        /// </summary>
        /// <param name="source">Stream containing data to be encrypted and written.</param>
        /// <param name="length">Length of data to be written.</param>
        /// <param name="finishing"></param>
        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
        public long WriteExactly(System.IO.Stream source, long length, bool finishing = false)
        {
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Writing == false) {
                throw new InvalidOperationException(NotWritingError);
            }
            if (source == null) {
                throw new ArgumentNullException("source");
            }

            Task<long> task;
            try {
                task = WriteExactlyAsync(source, length, finishing);
                task.RunSynchronously();
            } catch (Exception e) {
                throw;
            }

            return task.Result;
        }


        /// <summary>
        ///     Encrypts and writes specified quantity of bytes exactly (after cipher transform) 
        ///     to the <see cref="Binding"/> asynchronously, such that <see cref="T:Binding.Position"/> 
        ///     position <c>p</c> will be <c>p + length</c> after finishing. 
        /// </summary>
        /// <remarks>
        ///     May have higher performance than <see cref="WriteExactly"/> due to 
        ///     implementation of concurrent stream buffer I/O and enciphering. 
        ///     Input from <paramref name="source"/> can be read into the input buffer 
        ///     at the same time it is also taken from that same buffer for encryption - 
        ///     as is the case for output.
        /// </remarks>
        /// <param name="source">Stream containing data to be encrypted and written.</param>
        /// <param name="length">Length of data to be written.</param>
        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
        public async Task<long> WriteExactlyAsync(System.IO.Stream source, long length, bool finishing)
        {
#if INCLUDE_CONTRACTS
            Contract.Requires(source != null);
            Contract.Requires(length >= 0);
#else
            if (source == null) {
                throw new ArgumentNullException("source");
            }
            if (length < 0) {
                throw new ArgumentException("length");
            }
#endif

            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Writing == false) {
                throw new InvalidOperationException(NotWritingError);
            }
            if (length < 1) {
                return 0;
            }

            var processingReturned = await ProcessAsync(length, source, Binding);
            
            BytesIn += processingReturned.Item1;
            BytesOut += processingReturned.Item2;

            return processingReturned.Item1;
        }

        /// <summary>
        ///     Performs encryption/decryption operations as necessary to fulfill requested 
        ///     <paramref name="length"/>, asynchronously.
        /// </summary>
        /// <param name="length">The length.</param>
        /// <param name="inStream">
        ///     The input stream - when encrypting, source data stream; 
        ///     when decrypting, stream <see cref="CipherStream.Binding"/>.
        /// </param>
        /// <param name="outStream">
        ///     The output stream - when encrypting, stream <see cref="CipherStream.Binding"/>; 
        ///     when decrypting, data destination stream.
        /// </param>
        /// <param name="finishing">if set to <c>true</c> [finishing].</param>
        /// <returns></returns>
        /// <exception cref="System.IO.EndOfStreamException">
        /// </exception>
        private async Task<Tuple<long, long>> ProcessAsync(
            long length, 
            System.IO.Stream inStream = null, 
            System.IO.Stream outStream = null, 
            bool finishing = false)
        {
            long totalIn = 0, totalOut = 0;

            if (inStream == null) {
                if (Writing) {
                    throw new ArgumentNullException("inStream");
                }
                inStream = _streamBinding;
            }
            if (outStream == null) {
                if (Writing == false) {
                    throw new ArgumentNullException("outStream");
                }
                outStream = _streamBinding;
            }

            // Fill, process, and write out any remainder
            totalIn += FillInputOperationBuffer(inStream, _opInBuffer, ref _opBufferOffset);
            if (_opBufferOffset == _opSize) {
                int processedRemainder = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _opBufferOffset = 0;
                length -= processedRemainder;
                _outBuffer.Put(_opOutBuffer, 0, processedRemainder);
            }
            
            Task<int> streamInReadTask = null;
            Task streamOutWriteTask = null;
            // Pending I/O requests (for above tasks) - if either task completes with guard value still set, there is an error in implementation.
            int streamInReadRequested = -1; // streamInReadTask should never complete with result -1
            int streamOutWriteRequested = -1; // streamOutWriteTask should never complete with this variable set to -1

            bool eosReached = false; // EOS = end of stream

            while (length > 0) {
                // Prevent possible inbuffer underrun (proactively)
                if (_inBuffer.CurrentLength <= StreamBufferIoThreshold && eosReached == false) {
                    bool starving = _inBuffer.CurrentLength < _opSize;
                    if (streamInReadTask == null) {
                        int idealReadQuantity;
                        if (starving) {
                            // Input materiel needed urgently!
                            idealReadQuantity = StreamBufferIoThreshold + _opSize;
                        } else {
                            // Read data needed, but hasn't reached starvation state yet (can continue processing)
                            idealReadQuantity = StreamBufferSize - _inBuffer.CurrentLength;
                        }
                        streamInReadRequested = Math.Min((int)length, idealReadQuantity);
                        streamInReadTask = _inBuffer.PutFromAsync(inStream, streamInReadRequested, CancellationToken.None);
                    }
                    if (starving || streamInReadTask.IsCompleted) {
                        // Await the task return value (amount actually read)
                        // If completed, should return immediately
                        int streamInReadReturned = await streamInReadTask;
                        streamInReadTask = null;
                        // Check if we got the requested quantity of data
                        Debug.Assert(streamInReadReturned >= 0, "Returned data length (streamInReadReturned) from read task (streamInReadTask) should not be negative.");
                        Debug.Assert(streamInReadRequested != -1, "Read task (streamInReadTask) should never be requested with length (streamInReadRequested) == -1");
                        totalIn += streamInReadReturned;
                        if (streamInReadReturned < streamInReadRequested) {
                            // EOS
                            int requiredReadLength;
                            if (Writing) {
                                requiredReadLength = (int)CalculateInputForOutput(length - _outBuffer.CurrentLength);
                            } else {
                                requiredReadLength = (int)(length - _inBuffer.CurrentLength);
                            }
                            if (_inBuffer.CurrentLength < requiredReadLength && finishing == false) {
                                throw new EndOfStreamException(Writing ? WritingExactlySourceEosError : ReadingExactlyBindingEosError);
                            }
                            eosReached = true;
                        }
                        if (Writing == false) {
                            length -= streamInReadReturned; // subtractive assignment to length    
                        }
                    }
                }
                // Prevent possible outbuffer overflow (proactively)
                if (_outBuffer.CurrentLength >= StreamBufferIoThreshold || eosReached) {
                    bool overflowing = _outBuffer.CurrentLength + _opSize > StreamBufferSize;
                    if (streamOutWriteTask == null) {
                        int idealWriteQuantity;
                        if (overflowing) {
                            // Output capacity needed urgently!
                            idealWriteQuantity = StreamBufferIoThreshold + _opSize;
                        } else {
                            // Data needing to be written, but hasn't reached overflow state yet (can continue processing)
                            idealWriteQuantity = _outBuffer.CurrentLength - _opSize;
                        }
                        streamOutWriteRequested = Math.Min((int)length, idealWriteQuantity);
                        streamOutWriteTask = _outBuffer.TakeToAsync(outStream, streamOutWriteRequested, CancellationToken.None);
                    } else if (overflowing || streamOutWriteTask.IsCompleted) {
                        // Await the task return value
                        // Cannot proceed until task completes! If already completed, should return immediately.
                        await streamOutWriteTask;
                        streamOutWriteTask = null;
                        Debug.Assert(streamOutWriteRequested != -1, "Read task (streamOutWriteTask) should never be requested with length (streamOutWriteRequested) == -1");
                        totalOut += streamOutWriteRequested;
                        if (Writing) {
                            length -= streamOutWriteRequested; // subtractive assignment to length    
                        }
                    }
                }

                // Take input from input ringbuffer
                _inBuffer.Take(_opInBuffer, 0, _opSize);
                // Do the actual processing (encryption/decryption)
                int iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                // Put output into output ringbuffer
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
            }

            Debug.Assert(length <= _outBuffer.CurrentLength);

            return new Tuple<long, long>(totalIn, totalOut);
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

            while (_inBuffer.CurrentLength >= _opSize) {
                _inBuffer.Take(_opInBuffer, _opBufferOffset, _opSize - _opBufferOffset);
                int iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _opBufferOffset = 0;
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
                if (_outBuffer.Spare <= _opSize) {
                    int writeOut = _outBuffer.CurrentLength;
                    _outBuffer.TakeTo(Binding, writeOut);
                }
                    
            }
            _outBuffer.TakeTo(Binding, _outBuffer.CurrentLength);
            _opBufferOffset = _inBuffer.CurrentLength;
            _inBuffer.Take(_opInBuffer, 0, _opBufferOffset);

            try {
                finalLength = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
                _opBufferOffset = 0;
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

            if (Finished) 
                _outBuffer.Take();

            if (_outBuffer.CurrentLength == 0) {
                int operationRemainder = _opSize - _opBufferOffset;
                // Take remainder data from inBuffer
                if (_inBuffer.CurrentLength > 0) {
                    int fromInBuffer = Math.Min(_inBuffer.CurrentLength, operationRemainder);
                    _inBuffer.Take(_opInBuffer, _opBufferOffset, fromInBuffer);
                    operationRemainder -= fromInBuffer;
                    _opBufferOffset += fromInBuffer;
                }
                // Take remainder data from stream Binding
                while (operationRemainder > 0) {
                    int fromInStream = _streamBinding.Read(_opInBuffer, _opBufferOffset, operationRemainder);
                    operationRemainder -= fromInStream;
                    _opBufferOffset += fromInStream;
                    BytesIn += fromInStream;
                    if (fromInStream == 0) {
                        // EOS
                        int finalByteQuantity = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
                        _opBufferOffset = 0;
                        _outBuffer.Put(_opOutBuffer, 0, finalByteQuantity);
                        Finish();
                        break;
                    }
                }
            }

            if (_opBufferOffset == _opSize) {
                // Op buffer is full, process an op block
                int iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                _outBuffer.Put(_opOutBuffer, 0, iterOut);
                _opBufferOffset = 0;
            }

            BytesOut++;
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

            while (count > 0) {
                totalIn += FillInputOperationBuffer(_streamBinding, _opInBuffer, ref _opBufferOffset);
                
                if (_opBufferOffset == _opSize) {
                    iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                    _outBuffer.Put(_opOutBuffer, 0, iterOut);
                } else {
                    // EOS: finish
                }




                
                totalOut += iterOut;
                offset += iterOut;
                count -= iterOut;





                int operationRemainder = _opSize - _opBufferOffset;
                if (operationRemainder > 0) {
                    int fromInBuffer = Math.Min(operationRemainder, _inBuffer.CurrentLength);
                    if (fromInBuffer > 0) {
                        _inBuffer.Take(_opInBuffer, _opBufferOffset, fromInBuffer);
                        operationRemainder -= fromInBuffer;
                        _opBufferOffset += fromInBuffer;
                    }

                    while (operationRemainder > 0) {
                        int fromInStream = _streamBinding.Read(_opInBuffer, _opBufferOffset, operationRemainder);
                        operationRemainder -= fromInStream;
                        _opBufferOffset += fromInStream;
                        totalIn += fromInStream;
                        if (fromInStream == 0) {
                            // EOS
                            int finalByteQuantity = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
                            _opBufferOffset = 0;
                            _outBuffer.Put(_opOutBuffer, 0, finalByteQuantity);
                            Finish();
                            break;
                        }
                    }
                }

                if (Finished == false) {
                    iterOut = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
                    _outBuffer.Put(_opOutBuffer, 0, iterOut);
                    totalOut += iterOut;
                    offset += iterOut;
                    count -= iterOut;
                } else if (_outBuffer.CurrentLength + _opOutBuffer.Length > _outBuffer.MaximumCapacity) {
                    int toOutput = Math.Min(count, _outBuffer.CurrentLength - _opSize);
                    _outBuffer.Take(buffer, offset, toOutput);
                    totalOut += toOutput;
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
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Writing) {
                throw new InvalidOperationException(NotReadingError);
            }
            if (destination == null) {
                throw new ArgumentNullException("destination");
            }
            if (length < 0) {
                throw new ArgumentException("Length must be positive.", "length");
            }

            Task<long> task;
            try {
                task = ReadExactlyAsync(destination, length, finishing);
                task.RunSynchronously();
            } catch (Exception e) {
                throw;
            }

            return task.Result;
        }


        public async Task<long> ReadExactlyAsync(System.IO.Stream destination, long length, bool finishing = false)
        {
            if (Writing) {
                throw new InvalidOperationException(NotReadingError);
            }
            if (destination == null) {
                throw new ArgumentNullException("destination");
            }
            if (length < 0) {
                throw new ArgumentException("Length must be positive.", "length");
            }

            if (length < 1) {
                return 0;
            }

            var processingReturned = await ProcessAsync(length, Binding, destination);

            BytesIn += processingReturned.Item1;
            BytesOut += processingReturned.Item2;

            return processingReturned.Item1;
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

        #region Reset capability

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

        #endregion

        #region Helper methods

        /// <summary>
        ///     Designed for use with the operation-in buffer '_opInBuffer' specifically, 
        ///     but this method should be able to be used in other contexts successfully, 
        ///     so long as some special conditions are met: see documentation remarks.
        /// </summary>
        /// <remarks>
        ///     This method should be able to be used with any byte array buffer in an 
        ///     <i>input</i> use-case, provided that: 
        ///     <list type="number">
        ///         <li>Input is taken from the input ringbuffer '_inBuffer' preferentially.</li>
        ///         <li>If and only if this is exhausted (fallback), input is taken from a <paramref name="source"/> stream.</li>
        ///     </list>
        ///     <para>
        ///     Caution: the aforementioned conditions MUST be met in full! 
        ///     Failure to ensure this will cause data ordering and/or loss errors (fatal to cipher functioning), to both adapted and 
        ///     primary use-cases - e.g. primary CipherStream functionality.
        ///     </para>
        /// </remarks>
        /// <param name="source">The source.</param>
        /// <param name="operationBuffer">The buffer.</param>
        /// <param name="operationBufferOffset">The offset.</param>
        /// <returns></returns>
        /// <exception cref="System.IO.EndOfStreamException"></exception>
        private int FillInputOperationBuffer(System.IO.Stream source, byte[] operationBuffer, ref int operationBufferOffset)
        {
            int inputTotal = 0;
            int remainder = operationBuffer.Length - operationBufferOffset;
            if (remainder > 0) {
                // Input buffer source
                int fromInBuffer = Math.Min(remainder, _inBuffer.CurrentLength);
                if (fromInBuffer > 0) {
                    _inBuffer.Take(operationBuffer, operationBufferOffset, fromInBuffer);
                    remainder -= fromInBuffer;
                    operationBufferOffset += fromInBuffer;
                }
                // Stream source fallback
                while (remainder > 0) {
                    int fromInStream = source.Read(operationBuffer, operationBufferOffset, remainder);
                    remainder -= fromInStream;
                    operationBufferOffset += fromInStream;
                    inputTotal += fromInStream;
                    if (fromInStream == 0) {
                        // EOS
                        // int finalByteQuantity = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
                        // offset = 0;
                        // _outBuffer.Put(_opOutBuffer, 0, finalByteQuantity);
                        // Finish();
                        break;
                    }
                }
            }

            return inputTotal;
        }






























//        private int HandleOperationRemainder(int remainder, byte[] buffer, ref int offset, ref int count)
//        {
//            int operationRemainder = _opSize - _opBufferOffset;
//            if (operationRemainder > 0) {
//                // Input buffer source
//                int fromInBuffer = Math.Min(operationRemainder, _inBuffer.CurrentLength);
//                if (fromInBuffer > 0) {
//                    _inBuffer.Take(_opInBuffer, _opBufferOffset, fromInBuffer);
//                    operationRemainder -= fromInBuffer;
//                    _opBufferOffset += fromInBuffer;
//                }
//                // Stream source fallback
//                while (operationRemainder > 0) {
//                    int fromInStream = _streamBinding.Read(_opInBuffer, _opBufferOffset, operationRemainder);
//                    operationRemainder -= fromInStream;
//                    _opBufferOffset += fromInStream;
//                    totalIn += fromInStream;
//                    if (fromInStream == 0) {
//                        // EOS
//                        int finalByteQuantity = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
//                        _opBufferOffset = 0;
//                        _outBuffer.Put(_opOutBuffer, 0, finalByteQuantity);
//                        Finish();
//                        break;
//                    }
//                }
//            }
//
//
//            buffer.DeepCopy_NoChecks(offset, _opInBuffer, _opBufferOffset, remainder);
//            int processedRemainder = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
//            _opBufferOffset = 0;
//            offset += remainder;
//            count -= remainder;
//            _outBuffer.Put(_opOutBuffer, 0, processedRemainder);
//
//            return processedRemainder;
//        }
//
//        private int FillAndProcessOperationRemainder(byte[] buffer, int remainder, ref int offset, ref int count)
//        {
//            buffer.DeepCopy_NoChecks(offset, _opInBuffer, _opBufferOffset, remainder);
//            int processedRemainder = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
//            _opBufferOffset = 0;
//            offset += remainder;
//            count -= remainder;
//            _outBuffer.Put(_opOutBuffer, 0, processedRemainder);
//
//            return processedRemainder;
//        }
//
//
//        private int HandleOperationInputRemainder(int remainder, System.IO.Stream source, ref long length)
//        {
//            if (remainder > 0) {
//                int fromInBuffer = Math.Min(remainder, _inBuffer.CurrentLength);
//                if (fromInBuffer > 0) {
//                    _inBuffer.Take(_opInBuffer, _opBufferOffset, fromInBuffer);
//                    remainder -= fromInBuffer;
//                    _opBufferOffset += fromInBuffer;
//                }
//
//                while (remainder > 0) {
//                    int fromInStream = _streamBinding.Read(_opInBuffer, _opBufferOffset, remainder);
//                    remainder -= fromInStream;
//                    _opBufferOffset += fromInStream;
//                    totalIn += fromInStream;
//                    if (fromInStream == 0) {
//                        // EOS
//                        int finalByteQuantity = _cipher.ProcessFinal(_opInBuffer, 0, _opBufferOffset, _opOutBuffer, 0);
//                        _opBufferOffset = 0;
//                        _outBuffer.Put(_opOutBuffer, 0, finalByteQuantity);
//                        Finish();
//                        break;
//                    }
//                }
//            }
//
//            int readRemainder = source.Read(_opInBuffer, _opBufferOffset, remainder);
//            if (readRemainder > remainder) {
//                throw new EndOfStreamException();
//            }
//            int processedRemainder = _cipher.ProcessBytes(_opInBuffer, 0, _opOutBuffer, 0);
//            _opBufferOffset = 0;
//            length -= processedRemainder;
//            _outBuffer.Put(_opOutBuffer, 0, processedRemainder);
//
//            return processedRemainder;
//        }

        /// <summary>
        /// Calculates the amount of input required to generate <paramref name="length"/> of output.
        /// </summary>
        /// <param name="length">The length of output desired.</param>
        /// <param name="finish">If set to <c>true</c>, [finish] the encryption/decryption process by finalising the cipher.</param>
        /// <returns></returns>
        public long CalculateInputForOutput(long length)
        {
            double nativeOperationsFp = (double)length / _opSize_CipherNative;
            if (_finalisingOnOpBoundaryRequired)
                nativeOperationsFp = Math.Ceiling(nativeOperationsFp);
            long inputLength = (long)nativeOperationsFp * (_opSize_CipherNative - _maxCipherOutputDelta);
            return inputLength;
        }

        /// <summary>
        /// Calculates the amount of output generated from <paramref name="length"/> of input.
        /// </summary>
        /// <param name="length">The length of input available.</param>
        /// <param name="finish">If set to <c>true</c>, [finish] the encryption/decryption process by finalising the cipher.</param>
        /// <returns></returns>
        public long CalculateOutputForInput(long length, bool finish = true)
        {
            double nativeOperationsFp = (double)length / _opSize_CipherNative;
            if (_finalisingOnOpBoundaryRequired)
                nativeOperationsFp = Math.Ceiling(nativeOperationsFp);
            long outputLength = (long)nativeOperationsFp * (_opSize_CipherNative + _maxCipherOutputDelta);
            return outputLength;
        }

        #endregion
    
    }

//    internal class CipherRingBuffer : SequentialRingBuffer
//    {
//        public CipherRingBuffer(int maximumCapacity, byte[] buffer = null, bool allowOverwrite = false)
//            : base(maximumCapacity, buffer, allowOverwrite) {}
//    }
}
