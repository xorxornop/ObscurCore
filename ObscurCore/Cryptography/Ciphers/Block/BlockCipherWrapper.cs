using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.Cryptography.Ciphers.Block.Padding;

namespace ObscurCore.Cryptography.Ciphers.Block
{
    /// <summary>
    /// Provides a wrapper for I/O operations with block ciphers, including padding support.
    /// </summary>
    /// <remarks>
    /// No buffering support is included for performance and precise control. 
    /// All I/O operations must therefore be tailored to cipher block size. 
    /// Similarly, a minimum of error-checking is done, and so should be done by the caller.
    /// </remarks>
    public sealed class BlockCipherWrapper : ICipherWrapper
    {
        private readonly IBlockCipher _cipher;
        private readonly IBlockCipherPadding _padding;
        private readonly int _blockSize;

        public bool Encrypting { get; private set; }

        public int BlockSize { get { return _blockSize; } }
        public int OperationSize { get { return _blockSize; } }


        /// <summary>
        /// Initializes a new instance of the <see cref="T:System.Object"/> class.
        /// </summary>
        public BlockCipherWrapper(bool encrypting, IBlockCipher cipher, IBlockCipherPadding padding) {
            _cipher = cipher;
            _padding = padding;
            Encrypting = encrypting;
            _blockSize = cipher.BlockSize;
        }

        /// <summary>
        /// Process a whole block of plaintext/ciphertext into the opposite form.
        /// </summary>
        /// <param name="input">Array to take input bytes from.</param>
        /// <param name="inputOffset">Position at which to read from.</param>
        /// <param name="output">Array to put output bytes in.</param>
        /// <param name="outputOffset">Position at which to write to.</param>
        public int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset) {
            if (input.Length > inputOffset + _blockSize) {
                throw new ArgumentException("Input array not large enough to supply input block.", "input");
            } else if (output.Length < outputOffset + _blockSize) {
                throw new ArgumentException("Output array not large enough to accept output block.", "output");
            }
            return _cipher.ProcessBlock(input, inputOffset, output, outputOffset);
        }

        /// <summary>
        /// Process final block of plaintext/ciphertext.
        /// </summary>
        /// <param name="finalBytes">Block of plaintext/ciphertext to process as final block.</param>
        /// <returns></returns>
        public byte[] ProcessFinal(byte[] finalBytes) {
            var workingBlock = new byte[_blockSize];
            byte[] outputBlock;

            if (Encrypting) {
                if (_cipher.IsPartialBlockOkay) {
                    // Output block is truncated size
                    outputBlock = new byte[finalBytes.Length];
                    Array.Copy(finalBytes, workingBlock, finalBytes.Length);
                    // Padding is pointless if cipher supports partial blocks, so we won't even support it
                    _cipher.ProcessBlock(workingBlock, 0, workingBlock, 0);
                    Array.Copy(workingBlock, outputBlock, finalBytes.Length);
                } else {
                    // Output block is full block size
                    outputBlock = new byte[_blockSize];
                    Array.Copy(finalBytes, outputBlock, finalBytes.Length);
                    // Padding is required
                    _padding.AddPadding(outputBlock, finalBytes.Length);
                    _cipher.ProcessBlock(outputBlock, 0, outputBlock, 0);
                }
                Reset();
            } else {
                if (_cipher.IsPartialBlockOkay) {
                    outputBlock = new byte[finalBytes.Length];
                    Array.Copy(finalBytes, workingBlock, finalBytes.Length);
                    _cipher.ProcessBlock(workingBlock, 0, workingBlock, 0);
                    Array.Copy(workingBlock, outputBlock, finalBytes.Length);
                    Reset();
                } else {
                    if (finalBytes.Length != _blockSize) {
                        throw new CryptoException();
                    }
                    Array.Copy(finalBytes, workingBlock, finalBytes.Length);
                    _cipher.ProcessBlock(workingBlock, 0, workingBlock, 0);
                    try {
                        // Determine the number of padding bytes
                        var paddingByteCount = _padding.PadCount(workingBlock);
                        outputBlock = new byte[_blockSize - paddingByteCount];
                        Array.Copy(workingBlock, outputBlock, outputBlock.Length);
                    }
                    finally {
                        Reset();
                    }
                }
            }

            return outputBlock;
        }

        public void Reset() {
            _cipher.Reset();
        }
    }
}
