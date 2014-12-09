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
    ///     Decorating stream implementing authentication operations with a MAC function.
    /// </summary>
    public sealed class MacStream : Stream, IStreamDecorator
    {
        private const int BufferSize = 4096; // 8 KB
        private readonly bool _closeOnDispose;
        private readonly IMac _mac;
        private readonly byte[] _output;
        private byte[] _buffer;

        private bool _disposed;
        private Stream _streamBinding;

        /// <summary>
        ///     Initialises a new instance of the <see cref="MacStream" /> class.
        /// </summary>
        /// <param name="binding">Stream to write to or read from.</param>
        /// <param name="writing">If set to <c>true</c>, writing; otherwise, reading.</param>
        /// <param name="function">MAC function to instantiate.</param>
        /// <param name="key">Cryptographic key to use in the MAC operation.</param>
        /// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
        /// <param name="nonce"></param>
        /// <param name="closeOnDispose">If set to <c>true</c>, bound stream will be closed on dispose/close.</param>
        /// <param name="config"></param>
        public MacStream(Stream binding, bool writing, MacFunction function, byte[] key, byte[] salt = null,
                         byte[] config = null, byte[] nonce = null, bool closeOnDispose = true)
        {
            Contract.Requires<ArgumentNullException>(binding != null);
            Contract.Requires<ArgumentNullException>(key != null);

            _streamBinding = binding;
            Writing = writing;
            _closeOnDispose = closeOnDispose;

            _mac = AuthenticatorFactory.CreateMacPrimitive(function, key, salt, config, nonce);
            _output = new byte[_mac.OutputSize];
            _buffer = new byte[BufferSize];
        }

        /// <summary>
        ///     Initialises a new instance of the <see cref="MacStream" /> class.
        /// </summary>
        /// <param name="binding">Stream to write to or read from.</param>
        /// <param name="writing">If set to <c>true</c>, writing; otherwise, reading.</param>
        /// <param name="function">MAC function to instantiate.</param>
        /// <param name="key">Cryptographic key to use in the MAC operation.</param>
        /// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
        /// <param name="output">Byte array where the finished MAC will be output to. Does not need to be initialised.</param>
        /// <param name="config"></param>
        /// <param name="nonce"></param>
        /// <param name="closeOnDispose">If set to <c>true</c>, bound stream will be closed on dispose/close.</param>
        public MacStream(Stream binding, bool writing, MacFunction function, out byte[] output, byte[] key,
                         byte[] salt = null,
                         byte[] config = null, byte[] nonce = null, bool closeOnDispose = true)
            : this(binding, writing, function, key, salt, config, nonce, closeOnDispose)
        {
            output = _output;
        }

        public MacStream(Stream binding, bool writing, IAuthenticationConfiguration config, byte[] key,
                         bool closeOnDispose = true)
        {
            Contract.Requires<ArgumentNullException>(binding != null);
            Contract.Requires<ArgumentNullException>(key != null);

            _streamBinding = binding;
            Writing = writing;
            _closeOnDispose = closeOnDispose;

            if (config.FunctionType != AuthenticationFunctionType.Mac) {
                throw new ConfigurationInvalidException("Configuration specifies function type other than MAC.");
            }

            _mac = AuthenticatorFactory.CreateMacPrimitive(config.FunctionName.ToEnum<MacFunction>(), key, config.Salt,
                config.FunctionConfiguration, config.Nonce);
            _output = new byte[_mac.OutputSize];
        }

        public MacStream(Stream binding, bool writing, IAuthenticationConfiguration config, out byte[] output,
                         byte[] key,
                         bool closeOnDispose = true) : this(binding, writing, config, key, closeOnDispose)
        {
            output = _output;
        }

        /// <summary>
        ///     Initialises a MAC authenticator stream using a pre-initialised MAC primitive.
        /// </summary>
        /// <param name="binding">Stream to write to or read from.</param>
        /// <param name="writing">If set to <c>true</c>, writing; otherwise, reading.</param>
        /// <param name="macPrimitive">MAC primitive to use for authentication.</param>
        /// <param name="closeOnDispose">If set to <c>true</c>, bound stream will be closed on dispose/close.</param>
        public MacStream(Stream binding, bool writing, IMac macPrimitive, bool closeOnDispose = true)
        {
            Contract.Requires<ArgumentNullException>(binding != null);
            Contract.Requires<ArgumentNullException>(macPrimitive != null);

            _streamBinding = binding;
            Writing = writing;
            _closeOnDispose = closeOnDispose;

            _mac = macPrimitive;
            _output = new byte[_mac.OutputSize];
        }

        /// <summary>
        ///     Initialises a MAC authenticator stream using a pre-initialised MAC primitive.
        /// </summary>
        /// <param name="binding">StreamBinding.</param>
        /// <param name="writing">If set to <c>true</c> writing.</param>
        /// <param name="macPrimitive">MAC primitive to use for authentication.</param>
        /// <param name="output">Byte array where the finished MAC will be output to. Does not need to be initialised.</param>
        /// <param name="closeOnDispose">If set to <c>true</c> close on dispose.</param>
        public MacStream(Stream binding, bool writing, IMac macPrimitive, out byte[] output, bool closeOnDispose = true)
            : this(binding, writing, macPrimitive, closeOnDispose)
        {
            output = _output;
        }

        /// <summary>
        ///     The output/digest of the internal hash function. Zeroed if function is not finished.
        /// </summary>
        public byte[] Mac
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
            _mac.BlockUpdate(buffer, offset, count);

            BytesIn += count;
            BytesOut += count;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Contract.Requires(buffer != null);
            Contract.Requires(offset >= 0);
            Contract.Requires(count > 0);
            CheckIfCanDecorate();

            int readBytes = _streamBinding.Read(buffer, offset, count);
            if (readBytes > 0) {
                _mac.BlockUpdate(buffer, offset, readBytes);
            }

            BytesIn += readBytes;
            BytesOut += readBytes;

            return readBytes;
        }

        /// <summary>
        ///     Write exact quantity of bytes (after decoration) to the destination.
        /// </summary>
        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
        /// <param name="source">Source.</param>
        /// <param name="length">Length.</param>
        public long WriteExactly(Stream source, long length, bool finishing = false)
        {
            Contract.Requires(source != null);
            Contract.Requires(length > 0);
            CheckIfCanDecorate();

            long totalIn = 0;
            while (length > 0) {
                int iterIn = source.Read(_buffer, 0, (int) Math.Min(BufferSize, length));
                if (iterIn == 0) {
                    throw new EndOfStreamException();
                }
                totalIn += iterIn;
                _mac.BlockUpdate(_buffer, 0, iterIn);
                _streamBinding.Write(_buffer, 0, iterIn);
                length -= iterIn;
            }

            BytesIn += totalIn;
            BytesOut += totalIn;

            return totalIn;
        }

        public long ReadExactly(Stream destination, long length, bool finishing = false)
        {
            Contract.Requires<ArgumentNullException>(destination != null);
            CheckIfCanDecorate();

            long totalIn = 0;
            while (length > 0) {
                int iterIn = Binding.Read(_buffer, 0, (int) Math.Min(BufferSize, length));
                if (iterIn == 0) {
                    throw new EndOfStreamException();
                }
                totalIn += iterIn;
                _mac.BlockUpdate(_buffer, 0, iterIn);
                destination.Write(_buffer, 0, iterIn);
                length -= iterIn;
            }
            if (finishing) {
                Finish();
            }

            BytesIn += totalIn;
            BytesOut += totalIn;

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

        /// <summary>
        ///     Clears all buffers for this stream and causes any buffered data to be written to the underlying device.
        /// </summary>
        /// <exception cref="T:System.IO.IOException">An I/O error occurs. </exception>
        public override void Flush()
        {
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }

            _streamBinding.Flush();
        }

        public override void WriteByte(byte b)
        {
            base.WriteByte(b);
            _mac.Update(b);

            BytesIn++;
            BytesOut++;
        }

        public override int ReadByte()
        {
            int readByte = base.ReadByte();
            if (readByte >= 0) {
                _mac.Update((byte) readByte);
            }

            BytesIn++;
            BytesOut++;

            return readByte;
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


        public void Update(byte[] buffer, int offset, int count)
        {
            CheckIfCanDecorate();

            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            }

            //BytesIn += count;
            _mac.BlockUpdate(buffer, offset, count);
        }

        /// <summary>
        ///     Finish the MAC operation manually.
        ///     Unnecessary to use, as this is also accomplished by closing/disposing the stream.
        /// </summary>
        public void Finish()
        {
            if (_disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
            if (Finished) {
                return;
            }

            _mac.DoFinal(_output, 0);
            Finished = true;
        }

        public void Reset()
        {
            _mac.Reset();
            _output.SecureWipe();

            BytesIn = 0;
            BytesOut = 0;
            Finished = false;
        }

        public void ReassignBinding(Stream newBinding, bool reset = true, bool finish = false)
        {
            Contract.Requires(newBinding != null);

            if (finish) {
                Finish();
            }
            if (reset) {
                Reset();
            }

            _streamBinding = newBinding;
        }
    }
}
