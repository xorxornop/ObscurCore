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
using Obscur.Core.DTO;

namespace Obscur.Core.Cryptography.Authentication
{
    /// <summary>
    ///     Decorating stream implementing integrity/authentication operations with a hash/digest function.
    /// </summary>
    public sealed class HashStream : Stream, IStreamDecorator
    {
        private const int BufferSize = 8192; // 8 KB
        private readonly bool _closeOnDispose;
        private readonly IHash _digest;
        private readonly byte[] _output;
        private byte[] _buffer;

        private bool _disposed;
        private Stream _streamBinding;

        /// <summary>
        ///     Initializes a new instance of the <see cref="HashStream" /> class.
        /// </summary>
        /// <param name="binding">Stream to write to or read from.</param>
        /// <param name="writing">If set to <c>true</c>, writing; otherwise, reading.</param>
        /// <param name="function">Hash/digest function to instantiate.</param>
        /// <param name="output">Byte array where the finished hash will be output to.</param>
        /// <param name="closeOnDispose">If set to <c>true</c>, bound stream will be closed on dispose/close.</param>
        public HashStream(Stream binding, bool writing, HashFunction function, out byte[] output,
                          bool closeOnDispose = true)
        {
            Contract.Requires<ArgumentNullException>(binding != null);

            _streamBinding = binding;
            Writing = writing;
            _closeOnDispose = closeOnDispose;

            _digest = AuthenticatorFactory.CreateHashPrimitive(function);
            _buffer = new byte[BufferSize];
            _output = new byte[_digest.OutputSize];
            output = _output;
        }

        public HashStream(Stream binding, bool writing, IAuthenticationConfiguration config,
                          bool closeOnDispose = true)
        {
            Contract.Requires(binding != null);

            _streamBinding = binding;
            Writing = writing;
            _closeOnDispose = closeOnDispose;

            if (config.FunctionType != AuthenticationFunctionType.Mac) {
                throw new ConfigurationInvalidException("Configuration specifies function type other than MAC.");
            }

            _digest = AuthenticatorFactory.CreateHashPrimitive(config.FunctionName.ToEnum<HashFunction>());
            _buffer = new byte[BufferSize];
            _output = new byte[_digest.OutputSize];
        }

        /// <summary>
        ///     The output/digest of the internal hash function. Zeroed if function is not finished.
        /// </summary>
        public byte[] Hash
        {
            get { return _output; }
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

        public bool Finished { get; private set; }

        #region IStreamDecorator Members

        /// <summary>
        ///     Stream that decorator writes to or reads from.
        /// </summary>
        public Stream Binding
        {
            get { return _streamBinding; }
        }

        public bool Writing { get; private set; }

        public long BytesIn { get; private set; }

        public long BytesOut { get; private set; }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Contract.Requires(buffer != null);
            Contract.Requires(offset >= 0);
            Contract.Requires(count > 0);

            CheckIfCanDecorate();

            _streamBinding.Write(buffer, offset, count);
            _digest.BlockUpdate(buffer, offset, count);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Contract.Requires(buffer != null);
            Contract.Requires(offset >= 0);
            Contract.Requires(count > 0);
            CheckIfCanDecorate();

            int readBytes = _streamBinding.Read(buffer, offset, count);
            if (readBytes > 0) {
                _digest.BlockUpdate(buffer, offset, readBytes);
            }
            return readBytes;
        }

        public long WriteExactly(Stream source, long length)
        {
            Contract.Requires<ArgumentNullException>(source != null);
            Contract.Requires<ArgumentOutOfRangeException>(length >= 0);

            CheckIfCanDecorate();

            if (_buffer == null) {
                _buffer = new byte[BufferSize];
            }
            long totalIn = 0;
            while (length > 0) {
                int iterIn = source.Read(_buffer, 0, (int) Math.Min(BufferSize, length));
                if (iterIn == 0) {
                    throw new EndOfStreamException();
                }
                totalIn += iterIn;
                _digest.BlockUpdate(_buffer, 0, iterIn);
                _streamBinding.Write(_buffer, 0, iterIn);
                length -= iterIn;
            }

            return totalIn;
        }

        public long ReadExactly(Stream destination, long length, bool finishing = false)
        {
            Contract.Requires<ArgumentNullException>(destination != null);
            Contract.Requires<ArgumentOutOfRangeException>(length >= 0);

            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }

            if (_buffer == null) {
                _buffer = new byte[BufferSize];
            }
            long totalIn = 0;
            while (length > 0) {
                int iterIn = Binding.Read(_buffer, 0, (int) Math.Min(BufferSize, length));
                if (iterIn == 0) {
                    throw new EndOfStreamException();
                }
                totalIn += iterIn;
                _digest.BlockUpdate(_buffer, 0, iterIn);
                destination.Write(_buffer, 0, iterIn);
                length -= iterIn;
            }
            if (finishing) {
                Finish();
            }

            return totalIn;
        }

        #endregion

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
            _disposed = true;
        }

        public override void WriteByte(byte b)
        {
            CheckIfCanDecorate();

            _streamBinding.WriteByte(b);
            _digest.Update(b);
        }

        public override int ReadByte()
        {
            CheckIfCanDecorate();

            int readByte = _streamBinding.ReadByte();
            if (readByte >= 0) {
                _digest.Update((byte) readByte);
            }
            return readByte;
        }

        /// <summary>
        ///     When overridden in a derived class, clears all buffers for this stream and causes any buffered data to be written
        ///     to the underlying device.
        /// </summary>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        public override void Flush()
        {
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }

            _streamBinding.Flush();
        }

        /// <summary>
        ///     When overridden in a derived class, sets the position within the current stream.
        /// </summary>
        /// <returns>
        ///     The new position within the current stream.
        /// </returns>
        /// <param name="offset">A byte offset relative to the <paramref name="origin" /> parameter. </param>
        /// <param name="origin">
        ///     A value of type <see cref="T:System.IO.SeekOrigin" /> indicating the reference point used to
        ///     obtain the new position.
        /// </param>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        /// <exception cref="T:System.NotSupportedException">
        ///     The stream does not support seeking, such as if the stream is
        ///     constructed from a pipe or console output.
        /// </exception>
        /// <exception cref="T:System.ObjectDisposedException">Methods were called after the stream was closed. </exception>
        public override long Seek(long offset, SeekOrigin origin)
        {
            CheckIfCanDecorate();

            if (CanSeek) {
                return _streamBinding.Seek(offset, origin);
            }
            throw new InvalidOperationException();
        }

        /// <summary>
        ///     When overridden in a derived class, sets the length of the current stream.
        /// </summary>
        /// <param name="value">The desired length of the current stream in bytes. </param>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        /// <exception cref="T:System.NotSupportedException">
        ///     The stream does not support both writing and seeking, such as if the
        ///     stream is constructed from a pipe or console output.
        /// </exception>
        /// <exception cref="T:System.ObjectDisposedException">Methods were called after the stream was closed. </exception>
        public override void SetLength(long value)
        {
            CheckIfCanDecorate();

            _streamBinding.SetLength(value);
        }

        public void Finish()
        {
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Finished) {
                return;
            }

            _digest.DoFinal(_output, 0);
            Finished = true;
        }

        public void Reset()
        {
            _digest.Reset();
            _output.SecureWipe();

            BytesIn = 0;
            BytesOut = 0;
            Finished = false;
        }
    }
}
