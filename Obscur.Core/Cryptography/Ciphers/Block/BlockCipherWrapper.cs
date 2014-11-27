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
using Obscur.Core.Cryptography.Ciphers.Block.Padding;
using PerfCopy;

namespace Obscur.Core.Cryptography.Ciphers.Block
{
    /// <summary>
    ///     Provides a wrapper for I/O operations with block ciphers, 
    ///     including modes of operation and padding support.
    /// </summary>
    /// <remarks>
    ///     No buffering support is included for performance and precise control.
    ///     All I/O operations must therefore be tailored to cipher block size.
    ///     Similarly, a minimum of error-checking is done, and so should be done by the caller.
    /// </remarks>
    public sealed class BlockCipherWrapper : ICipherWrapper
    {
        private readonly int _blockSize;
        private readonly BlockCipherModeBase _cipherCompound; // compound primitive: { cipher + mode }
        private readonly IBlockCipherPadding _padding;

        /// <summary>
        ///     Initializes a new <see cref="BlockCipherWrapper" />.
        /// </summary>
        /// <param name="encrypting">If set to <c>true</c> encrypting.</param>
        /// <param name="cipher">Cipher to wrap.</param>
        /// <param name="padding">Padding scheme used with the cipher. Null if none.</param>
        public BlockCipherWrapper(bool encrypting, BlockCipherModeBase cipher, IBlockCipherPadding padding)
        {
            if (cipher == null) {
                throw new ArgumentNullException("cipher");
            }

            Encrypting = encrypting;
            _cipherCompound = cipher;
            _padding = padding;
            _blockSize = cipher.BlockSize;
        }

        /// <summary>
        /// Block size of the cipher in bytes.
        /// </summary>
        public int BlockSize
        {
            get { return _blockSize; }
        }

        /// <inheritdoc />
        public bool Encrypting { get; private set; }

        /// <inheritdoc />
        public int OperationSize
        {
            get { return _blockSize; }
        }

        /// <summary>
        /// Name of the block cipher complex, including mode of operation, and padding (where applicable).
        /// </summary>
        public string AlgorithmName
        {
            get {
                if (_padding == null) {
                    return _cipherCompound.AlgorithmName;
                }
                return String.Format("{0}/{1}", _cipherCompound.AlgorithmName, _padding.PaddingName);
            }
        }

        public string DisplayName
        {
            get {
                if (_padding == null) {
                    return _cipherCompound.AlgorithmName;
                }
                return String.Format("{0} with {1} padding", _cipherCompound.AlgorithmName, _padding.PaddingName);
            }
        }

        internal BlockCipherBase Cipher
        {
            get { return _cipherCompound.Cipher; }
        }

        internal BlockCipherModeBase Mode
        {
            get { return _cipherCompound; }
        }

        /// <summary>
        ///     Identity of the cipher.
        /// </summary>
        public BlockCipher CipherIdentity
        {
            get { return _cipherCompound.CipherIdentity; }
        }

        /// <summary>
        ///     Identity of the mode of operation.
        /// </summary>
        public BlockCipherMode ModeIdentity
        {
            get { return _cipherCompound.ModeIdentity; }
        }

        /// <inheritdoc />
        public int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            if (input.Length < inputOffset + _blockSize) {
                throw new ArgumentException("Input array not large enough to supply input block.", "input");
            }
            if (output.Length < outputOffset + _blockSize) {
                throw new ArgumentException("Output array not large enough to accept output block.", "output");
            }
            return _cipherCompound.ProcessBlock(input, inputOffset, output, outputOffset);
        }

        /// <inheritdoc />
        public int ProcessFinal(byte[] input, int inputOffset, int length, byte[] output, int outputOffset)
        {
            var workingBlock = new byte[_blockSize];
            if (Encrypting) {
                if (_cipherCompound.IsPartialBlockOkay) {
                    // Output block is truncated size
                    // Padding is pointless if cipher supports partial blocks, so we won't even support it
                    _cipherCompound.ProcessBlock(input, inputOffset, workingBlock, 0);
                    workingBlock.DeepCopy_NoChecks(0, output, outputOffset, length);
                } else {
                    // Output block is full block size
                    // Padding is required
                    input.DeepCopy_NoChecks(inputOffset, workingBlock, 0, _blockSize);
                    length += _padding.AddPadding(workingBlock, length);
                    _cipherCompound.ProcessBlock(workingBlock, 0, output, outputOffset);
                }
                Reset();
            } else {
                if (_cipherCompound.IsPartialBlockOkay) {
                    _cipherCompound.ProcessBlock(input, inputOffset, workingBlock, 0);
                    workingBlock.DeepCopy_NoChecks(0, output, outputOffset, length);
                    Reset();
                } else {
                    if (length != _blockSize) {
                        if (length == 0 && _padding != null) {
                            // Overran the end
                            if (outputOffset >= _blockSize) {
                                outputOffset -= _blockSize;
                            }
                            output.DeepCopy_NoChecks(outputOffset, workingBlock, 0, _blockSize);
                        } else {
                            throw new CryptoException();
                        }
                    } else {
                        // Normal padded block
                        _cipherCompound.ProcessBlock(input, inputOffset, workingBlock, 0);
                    }
                    try {
                        // Determine the number of padding bytes
                        var paddingByteCount = _padding.PadCount(workingBlock);
                        workingBlock.DeepCopy_NoChecks(0, output, outputOffset, _blockSize - paddingByteCount);
                        length -= paddingByteCount;
                    }
                    finally {
                        Reset();
                    }
                }
            }

            return length;
        }

        /// <inheritdoc />
        public void Reset()
        {
            _cipherCompound.Reset();
        }
    }
}
