//
//  Copyright 2014  Matthew Ducker
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

namespace ObscurCore.Cryptography.Ciphers.Stream
{
    /// <summary>
    ///     Base class for stream cipher implementations.
    /// </summary>
    public abstract class StreamCipherEngine
    {
        protected readonly StreamCipher CipherIdentity;

        protected bool IsInitialised;
        protected byte[] Key, Nonce;

        /// <summary>
        /// Instantiate a new stream cipher engine.
        /// </summary>
        /// <param name="cipherIdentity">Identity of the stream cipher.</param>
        protected StreamCipherEngine(StreamCipher cipherIdentity)
        {
            CipherIdentity = cipherIdentity;
            Key = null;
            Nonce = null;
        }

        /// <summary>
        ///     The name of the stream cipher algorithm, 
        ///     including any configuration-specific identifiers, 
        ///     e.g. Salsa20/16 (includes round count).
        /// </summary>
        public virtual string AlgorithmName
        {
            get { return CipherIdentity.ToString(); }
        }

        /// <summary>
        ///     Display-friendly name of the stream cipher.
        /// </summary>
        /// <value>The display name of the cipher.</value>
        public string DisplayName
        {
            get { return Athena.Cryptography.StreamCiphers[CipherIdentity].DisplayName; }
        }

        /// <summary>
        /// Identity of the cipher.
        /// </summary>
        public StreamCipher Identity
        {
            get { return CipherIdentity; }
        }

        /// <summary>
        ///      The size of operation in bytes the cipher implements internally, e.g. keystream buffer.
        ///  </summary><value>The size of the internal operation in bytes.</value>
        public abstract int StateSize { get; }

        /// <summary>
        ///      Initialise the cipher.
        ///  </summary>
        /// <param name="encrypting">
        ///      If <c>true</c> the cipher is initialised for encryption,
        ///      otherwise for decryption.
        ///  </param>
        /// <param name="key">Key for the cipher.</param>
        /// <param name="iv">Nonce/initialisation vector for the cipher, where applicable.</param>
        /// <exception cref="!:ArgumentException">
        ///      If the parameter argument is invalid (e.g. incorrect length).
        ///  </exception>
        public void Init(bool encrypting, byte[] key, byte[] iv)
        {
            if (key == null) {
                throw new ArgumentNullException("key", AlgorithmName + " initialisation requires a key.");
            } else if (
                key.Length.BytesToBits()
                   .IsOneOf(Athena.Cryptography.StreamCiphers[CipherIdentity].AllowableKeySizes) == false) {
                throw new ArgumentException(AlgorithmName + " does not support a " + key.Length + " byte key.");
            }
            this.Key = key;

            if (iv == null) {
                throw new ArgumentNullException("iv", AlgorithmName + " initialisation requires a nonce.");
            } else if (
                iv.Length.BytesToBits()
                  .IsOneOf(Athena.Cryptography.StreamCiphers[CipherIdentity].AllowableNonceSizes) == false) {
                throw new ArgumentException(AlgorithmName + " does not support a " + iv.Length + " byte nonce.",
                    "iv");
            }
            this.Nonce = iv;

            InitState();
        }

        /// <summary>
        /// Set up cipher's internal state.
        /// </summary>
        protected abstract void InitState();

        /// <summary>
        ///      Encrypt/decrypt a single byte.
        ///  </summary><param name="input">The byte to be processed.</param><returns>Result of processing the input byte.</returns>
        public abstract byte ReturnByte(byte input);

        /// <summary>
        ///     Encrypt/decrypt bytes from <paramref name="input"/> 
        ///     and put the result into <paramref name="output"/>. 
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///      The offset in <paramref name="input" /> at which the input data begins.
        ///  </param>
        /// <param name="length">Number of bytes to process.</param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outOff">
        ///      The offset in <paramref name="output" /> at which to write the output data to.
        ///  </param>
        /// <exception cref="InvalidOperationException">Cipher is not initialised.</exception>
        /// <exception cref="DataLengthException">
        ///      A input or output buffer is of insufficient length.
        ///  </exception>
        public void ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            if (IsInitialised == false) {
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
            }

            if ((inOff + length) > input.Length) {
                throw new DataLengthException("Input buffer too short.");
            }

            if ((outOff + length) > output.Length) {
                throw new DataLengthException("Output buffer too short.");
            }

            if (length < 1) {
                return;
            }

            ProcessBytesInternal(input, inOff, length, output, outOff);
        }

        /// <summary>
        ///      Reset the cipher to the same state as it was after the last init (if there was one).
        ///  </summary>
        public abstract void Reset();

        /// <summary>
        ///     Encrypt/decrypt bytes from <paramref name="input"/> and put the result into <paramref name="output"/>. 
        ///     Performs no checks on argument validity - use only when pre-validated!
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///      The offset in <paramref name="input" /> at which the input data begins.
        ///  </param>
        /// <param name="length">The number of bytes to be processed.</param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outOff">
        ///      The offset in <paramref name="output" /> at which to write the output data to.
        ///  </param>
        internal abstract void ProcessBytesInternal(byte[] input, int inOff, int length, byte[] output, int outOff);
    }
}
