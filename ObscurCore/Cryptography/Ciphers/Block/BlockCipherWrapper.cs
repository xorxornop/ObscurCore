using System;
using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;
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

		public string AlgorithmName {
			get { 
				if (_padding == null) {
					return _cipher.AlgorithmName;
				} else {
					return String.Format("{0}/{1}", _cipher.AlgorithmName, _padding.PaddingName);
				}
			} 
		}


		/// <summary>
		/// Initializes a new <see cref="ObscurCore.Cryptography.Ciphers.Block.BlockCipherWrapper"/>.
		/// </summary>
		/// <param name="encrypting">If set to <c>true</c> encrypting.</param>
		/// <param name="cipher">Cipher to wrap.</param>
		/// <param name="padding">Padding scheme used with the cipher. Null if none.</param>
		public BlockCipherWrapper(bool encrypting, IBlockCipher cipher, IBlockCipherPadding padding) {
			if (cipher == null) {
				throw new ArgumentNullException ("cipher");
			}

			Encrypting = encrypting;
			_cipher = cipher;
            _padding = padding;
            _blockSize = cipher.BlockSize;
        }

        /// <summary>
		/// Process a single block of plaintext/ciphertext into the opposite form.
        /// </summary>
        /// <param name="input">Array to take input bytes from.</param>
        /// <param name="inputOffset">Position at which to read from.</param>
        /// <param name="output">Array to put output bytes in.</param>
        /// <param name="outputOffset">Position at which to write to.</param>
        public int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset) {
			if (input.Length < inputOffset + _blockSize) {
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
		public int ProcessFinal(byte[] input, int inputOffset, int length, byte[] output, int outputOffset) {
			var workingBlock = new byte[_blockSize];
            if (Encrypting) {
                if (_cipher.IsPartialBlockOkay) {
                    // Output block is truncated size
                    // Padding is pointless if cipher supports partial blocks, so we won't even support it
					_cipher.ProcessBlock(input, inputOffset, workingBlock, 0);
					Array.Copy (workingBlock, 0, output, outputOffset, length);
                } else {
                    // Output block is full block size
                    // Padding is required
					Array.Copy(input, inputOffset, workingBlock, 0, _blockSize);
					length += _padding.AddPadding(workingBlock, length);
					_cipher.ProcessBlock(workingBlock, 0, output, outputOffset);
                }
                Reset();
            } else {
                if (_cipher.IsPartialBlockOkay) {
					_cipher.ProcessBlock(input, inputOffset, workingBlock, 0);
					Array.Copy (workingBlock, 0, output, outputOffset, length);
					Reset ();
                } else {
					if (length != _blockSize) {
						if(length == 0 && _padding != null) {
							// Overran the end
							if(outputOffset >= _blockSize) outputOffset -= _blockSize;
							Array.Copy (output, outputOffset, workingBlock, 0, _blockSize);
						} else {
							throw new CryptoException();
						}
					} else {
						// Normal padded block
						_cipher.ProcessBlock(input, inputOffset, workingBlock, 0);
					}
                    try {
                        // Determine the number of padding bytes
                        var paddingByteCount = _padding.PadCount(workingBlock);
						Array.Copy(workingBlock, 0, output, outputOffset, _blockSize - paddingByteCount);
						length -= paddingByteCount;
                    }
                    finally {
                        Reset();
                    }
                }
            }

			return length;
        }

        public void Reset() {
            _cipher.Reset();
        }
    }
}
