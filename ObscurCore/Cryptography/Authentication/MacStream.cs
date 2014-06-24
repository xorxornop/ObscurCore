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
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    ///     Decorating stream implementing authentication operations with a MAC function.
    /// </summary>
    public sealed class MacStream : DecoratingStream
    {
        private const int BufferSize = 4096;
        private readonly IMac _mac;
        private readonly byte[] _output;
        private byte[] _buffer;

        /// <summary>
        ///     Initialises a new instance of the <see cref="ObscurCore.Cryptography.Authentication.MacStream" /> class.
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
            : base(binding, writing, closeOnDispose)
        {
            _mac = AuthenticatorFactory.CreateMacPrimitive(function, key, salt, config, nonce);
            _output = new byte[_mac.MacSize];
        }

        /// <summary>
        ///     Initialises a new instance of the <see cref="ObscurCore.Cryptography.Authentication.MacStream" /> class.
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

        public MacStream(Stream binding, bool writing, IAuthenticationFunctionConfiguration config, byte[] key,
            bool closeOnDispose = true) : base(binding, writing, closeOnDispose)
        {
            if (config.FunctionType.ToEnum<VerificationFunctionType>() != VerificationFunctionType.Mac) {
                throw new ConfigurationInvalidException("Configuration specifies function type other than MAC.");
            }

            _mac = AuthenticatorFactory.CreateMacPrimitive(config.FunctionName.ToEnum<MacFunction>(), key, config.Salt,
                config.FunctionConfiguration, config.Nonce);
            _output = new byte[_mac.MacSize];
        }

        public MacStream(Stream binding, bool writing, IAuthenticationFunctionConfiguration config, out byte[] output,
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
            : base(binding, writing, closeOnDispose)
        {
            _mac = macPrimitive;
            _output = new byte[_mac.MacSize];
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

        public override void Write(byte[] buffer, int offset, int count)
        {
            base.Write(buffer, offset, count);
            _mac.BlockUpdate(buffer, offset, count);
        }

        public override void WriteByte(byte b)
        {
            base.WriteByte(b);
            _mac.Update(b);
        }

        public override int ReadByte()
        {
            int readByte = base.ReadByte();
            if (readByte >= 0) {
                _mac.Update((byte) readByte);
            }
            return readByte;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            }

            int readBytes = base.Read(buffer, offset, count);
            if (readBytes > 0) {
                _mac.BlockUpdate(buffer, offset, readBytes);
            }
            return readBytes;
        }

        /// <summary>
        ///     Write exact quantity of bytes (after decoration) to the destination.
        /// </summary>
        /// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
        /// <param name="source">Source.</param>
        /// <param name="length">Length.</param>
        public override long WriteExactlyFrom(Stream source, long length)
        {
            CheckIfCanDecorate();
            if (source == null) {
                throw new ArgumentNullException("source");
            }

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
                _mac.BlockUpdate(_buffer, 0, iterIn);
                StreamBinding.Write(_buffer, 0, iterIn);
                length -= iterIn;
            }

            return totalIn;
        }

        public override long ReadExactlyTo(Stream destination, long length, bool finishing = false)
        {
            CheckIfCanDecorate();
            if (destination == null) {
                throw new ArgumentNullException("destination");
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
                _mac.BlockUpdate(_buffer, 0, iterIn);
                destination.Write(_buffer, 0, iterIn);
                length -= iterIn;
            }
            if (finishing) {
                Finish();
            }

            return totalIn;
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
        protected override void Finish()
        {
            CheckIfCanDecorate();
            _mac.DoFinal(_output, 0);
            base.Finish();
        }

        protected override void Reset(bool finish = false)
        {
            base.Reset(finish);
            _mac.Reset();
            Array.Clear(_output, 0, _output.Length);
        }
    }
}
