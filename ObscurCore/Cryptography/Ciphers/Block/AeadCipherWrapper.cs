using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.Cryptography.Ciphers.Block.Modes;

namespace ObscurCore.Cryptography.Ciphers.Block
{
    /// <summary>
    /// Provides a wrapper for I/O operations with AEAD block ciphers.
    /// </summary>
    /// <remarks>
    /// No buffering support is included for performance and precise control. 
    /// All I/O operations must therefore be tailored to cipher block size. 
    /// Similarly, a minimum of error-checking is done, and so should be done by the caller.
    /// </remarks>
    public sealed class AeadCipherWrapper : ICipherWrapper
    {
        private readonly IAeadBlockCipher _cipher;

        private readonly int _blockSize;

        public bool Encrypting { get; private set; }

        public int BlockSize { get { return _blockSize; } }
        public int OperationSize { get { return _blockSize; } }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:System.Object"/> class.
        /// </summary>
        public AeadCipherWrapper(bool encrypting, IAeadBlockCipher cipher) {
            _cipher = cipher;
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
            } else if (output.Length < outputOffset + _cipher.GetUpdateOutputSize(_blockSize)) {
                throw new ArgumentException("Output array not large enough to accept output block.", "output");
            }

            return _cipher.ProcessBytes(input, inputOffset, _blockSize, output, outputOffset);
        }

        
        public int ProcessBytes(byte[] input, int inputOffset, int length, byte[] output, int outputOffset) {
            if (input.Length > inputOffset + BlockSize) {
                throw new ArgumentException("Input array not large enough to supply input block.", "input");
            } else if (output.Length < outputOffset + _cipher.GetUpdateOutputSize(length)) {
                throw new ArgumentException("Output array not large enough to accept output block.", "output");
            }
            return _cipher.ProcessBytes(input, inputOffset, length, output, outputOffset); 
        }

        /// <summary>
        /// Process final block of plaintext/ciphertext.
        /// </summary>
        /// <param name="finalBytes">Block of plaintext/ciphertext to process as final block.</param>
        /// <returns></returns>
        public byte[] ProcessFinal(byte[] finalBytes) {
            var outputLength = _cipher.GetOutputSize(finalBytes.Length);
            var outputBytes = new byte[outputLength];
            int preFinalLength = ProcessBytes(finalBytes, 0, finalBytes.Length, outputBytes, 0);
            _cipher.DoFinal(outputBytes, preFinalLength);

            return outputBytes;
        }

        public void Reset() {
            _cipher.Reset();
        }
    }
}
