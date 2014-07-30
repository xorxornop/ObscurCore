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

namespace ObscurCore.Cryptography.Ciphers.Block
{
    /// <summary>
    ///     Base class for block cipher implementations.
    /// </summary>
    public abstract class BlockCipherBase 
    {
        protected readonly BlockCipher CipherIdentity;
        protected byte[] Key;
        protected bool IsInitialised;
        protected bool Encrypting;

        private int _blockSize;

        protected BlockCipherBase(BlockCipher cipherIdentity, int? blockSize = null)
        {
            CipherIdentity = cipherIdentity;
            Key = null;
            _blockSize = blockSize ?? Athena.Cryptography.BlockCiphers[CipherIdentity].DefaultBlockSize.BitsToBytes();
        }

        /// <summary>
        ///      The name of the block cipher.
        ///  </summary>
        public virtual string AlgorithmName
        {
            get { return CipherIdentity.ToString(); }
        }

        /// <summary>
        ///      The size of block in bytes that the cipher processes.
        ///  </summary><value>Block size for this cipher in bytes.</value>
        public int BlockSize 
        {
            get { return _blockSize; }
        }

        /// <summary>
        ///      Initialise the cipher. Depending on the construction, an initialisation
        ///      vector may also be required to be supplied.
        ///  </summary><param name="encrypting">If set to <c>true</c> encrypting, otherwise decrypting.</param><param name="key">Key for the cipher (required).</param><param name="iv">Initialisation vector, if used.</param>
        public void Init(bool encrypting, byte[] key)
        {
            if (key == null) {
                throw new ArgumentNullException("key", AlgorithmName + " initialisation requires a key.");
            } else if (
                key.Length.BytesToBits()
                   .IsOneOf(Athena.Cryptography.BlockCiphers[CipherIdentity].AllowableKeySizes) == false) {
                throw new ArgumentException(AlgorithmName + " does not support a " + key.Length + " byte key.");
            }
            this.Key = key;
            Encrypting = encrypting;
            IsInitialised = true;

            InitState();
        }

        /// <summary>
        /// Set up cipher's internal state.
        /// </summary>
        protected abstract void InitState();

        /// <summary>
        ///     Encrypt/decrypt a block from <paramref name="input"/> 
        ///     and put the result into <paramref name="output"/>. 
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///      The offset in <paramref name="input" /> at which the input data begins.
        ///  </param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outOff">
        ///      The offset in <paramref name="output" /> at which to write the output data to.
        ///  </param>
        /// <returns>Number of bytes processed.</returns>
        /// <exception cref="InvalidOperationException">Cipher is not initialised.</exception>
        /// <exception cref="DataLengthException">
        ///      A input or output buffer is of insufficient length.
        ///  </exception>
        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            if (IsInitialised == false) {
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
            }

            if ((inOff + _blockSize) > input.Length) {
                throw new DataLengthException("Input buffer too short.");
            }

            if ((outOff + _blockSize) > output.Length) {
                throw new DataLengthException("Output buffer too short.");
            }

            return ProcessBlockInternal(input, inOff, output, outOff);
        }

        /// <summary>
        ///     Encrypt/decrypt a block from <paramref name="input"/> 
        ///     and put the result into <paramref name="output"/>. 
        ///     Performs no checks on argument validity - use only when arguments are pre-validated!
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///      The offset in <paramref name="input" /> at which the input data begins.
        ///  </param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outOff">
        ///      The offset in <paramref name="output" /> at which to write the output data to.
        ///  </param>
        /// <returns>Number of bytes processed.</returns>
        internal abstract int ProcessBlockInternal(byte[] input, int inOff, byte[] output, int outOff);

        /// <summary>
        ///      Reset the cipher to the same state as it was after the last init (if there was one).
        ///  </summary>
        public abstract void Reset();
    }
}
