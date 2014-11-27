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

namespace Obscur.Core.Cryptography.Ciphers.Stream
{
    /// <summary>
    ///     Provides a wrapper for I/O operations with stream ciphers.
    /// </summary>
    /// <remarks>
    ///     No buffering support is included for performance and precise control.
    ///     All I/O operations must therefore be tailored to cipher block/state size.
    ///     <para>
    ///     Similarly, a minimum of error-checking is done, 
    ///     and so should be done by the caller where necessary.
    ///     </para>
    /// </remarks>
    public sealed class StreamCipherWrapper : ICipherWrapper
    {
        private readonly StreamCipherEngine _cipher;
        private readonly int _strideSize;

        /// <summary>
        ///     Initialises a new <see cref="StreamCipherWrapper" />.
        /// </summary>
        /// <param name="encrypting">If set to <c>true</c> encrypting.</param>
        /// <param name="cipher">Cipher to wrap (must be pre-initialised).</param>
        /// <param name="strideIncreaseFactor">Factor to raise operation size by (size<superscript>x</superscript>).</param>
        public StreamCipherWrapper(bool encrypting, StreamCipherEngine cipher, int strideIncreaseFactor = 0)
        {
            if (cipher == null) {
                throw new ArgumentNullException("cipher");
            }
            if (strideIncreaseFactor < 0 || strideIncreaseFactor > 8) {
                throw new ArgumentOutOfRangeException("strideIncreaseFactor");
            }

            Encrypting = encrypting;
            _cipher = cipher;
            _strideSize = _cipher.StateSize << strideIncreaseFactor;
        }

        /// <inheritdoc />
        public bool Encrypting { get; private set; }

        /// <inheritdoc />
        public int OperationSize
        {
            get { return _strideSize; }
        }

        /// <inheritdoc />
        public string AlgorithmName
        {
            get { return _cipher.AlgorithmName; }
        }

        /// <summary>
        ///     Display-friendly name of the stream cipher.
        /// </summary>
        public string DisplayName
        {
            get { return _cipher.DisplayName; }
        }

        internal StreamCipherEngine Cipher
        {
            get { return _cipher; }
        }

        /// <summary>
        ///     Identity of the cipher.
        /// </summary>
        public StreamCipher CipherIdentity
        {
            get { return _cipher.Identity; }
        }

        /// <inheritdoc />
        public int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            _cipher.ProcessBytesInternal(input, inputOffset, _strideSize, output, outputOffset);
            return _strideSize;
        }

        /// <inheritdoc />
        public int ProcessFinal(byte[] input, int inputOffset, int length, byte[] output, int outputOffset)
        {
            if (length == 0) {
                return 0;
            }
            _cipher.ProcessBytesInternal(input, inputOffset, length, output, outputOffset);
            return length;
        }

        /// <inheritdoc />
        public void Reset()
        {
            _cipher.Reset();
        }
    }
}
