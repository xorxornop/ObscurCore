using System;
using ObscurCore.Cryptography.Ciphers.Information;

namespace ObscurCore.Cryptography.Ciphers.Block
{
    /// <summary>
    ///     Base class for block cipher mode of operation wrappers.
    /// </summary>
    public abstract class BlockCipherModeBase
    {
        /// <summary>
        /// If cipher and operation mode have been initialised.
        /// </summary>
        protected bool IsInitialised;

        /// <summary>
        ///     If cipher is encrypting, <c>true</c>, otherwise <c>false</c>.
        /// </summary>
        protected bool Encrypting;

        /// <summary>
        ///     Initialisation vector for the operation mode.
        /// </summary>
        protected byte[] IV;

        /// <summary>
        /// 
        /// </summary>
        protected int CipherBlockSize;

        protected BlockCipherBase BlockCipher;
        protected BlockCipherMode ModeIdentity;

        /// <summary>
        /// Instantiate the block cipher mode of operation.
        /// </summary>
        /// <param name="modeIdentity">Type of the mode of operation. Used to provide and verify configuration.</param>
        /// <param name="cipher">Block cipher to wrap with operation mode.</param>
        /// <param name="blockSize"></param>
        protected BlockCipherModeBase(BlockCipherMode modeIdentity, BlockCipherBase cipher, int? blockSize = null)
        {
            ModeIdentity = modeIdentity;
            BlockCipher = cipher;
            CipherBlockSize = blockSize ?? cipher.BlockSize;
        }

        /// <summary>
        ///     The name of the wrapped block cipher paired with the mode of operation, 
        ///     including any mode-configuration identifiers (e.g. CFB feedback size).
        ///  </summary>
        public string AlgorithmName
        {
            get { return BlockCipher.AlgorithmName + "/" + Athena.Cryptography.BlockCipherModes[ModeIdentity].Name; }
        }

        /// <summary>
        ///      The size of block in bytes that the cipher processes.
        ///  </summary>
        /// <value>Block size for this cipher in bytes.</value>
        public int BlockSize
        {
            get { return CipherBlockSize; }
        }

        /// <summary>
        ///      Initialise the wrapped block cipher, and mode of operation.
        ///  </summary>
        /// <param name="encrypting">If set to <c>true</c> encrypting, otherwise decrypting.</param>
        /// <param name="key">Key for the cipher.</param>
        /// <param name="iv">Initialisation vector for the mode of operation.</param>
        public void Init(bool encrypting, byte[] key, byte[] iv)
        {
            BlockCipher.Init(encrypting, key);

            int ivLengthBits = iv.Length.BytesToBits();
            if (iv == null) {
                throw new ArgumentNullException("iv", AlgorithmName + " initialisation requires an initialisation vector.");
            //} else if (
            //    ivLengthBits.IsOneOf(Athena.Cryptography.StreamCiphers[CipherIdentity].AllowableNonceSizes) == false) 
            //{
            //    throw new ArgumentException(AlgorithmName + " does not support a " + iv.Length + " byte nonce.",
            //        "iv");
            }
            this.IV = iv;

            Encrypting = encrypting;
            InitState(key);
            IsInitialised = true;
        }

        /// <summary>
        /// Set up cipher's internal state.
        /// </summary>
        protected abstract void InitState(byte[] key);

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

            if ((inOff + CipherBlockSize) > input.Length) {
                throw new DataLengthException("Input buffer too short.");
            }

            if ((outOff + CipherBlockSize) > output.Length) {
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
        ///     Whether a padding scheme is required for writing the final block.
        /// </summary>
        public bool IsPartialBlockOkay  {
            get {
                return Athena.Cryptography.BlockCipherModes[ModeIdentity].PaddingRequirement != PaddingRequirement.Always;
            }
        }

        /// <summary>
        ///     Reset the wrapped cipher and this operation mode to the same state 
        ///     as it was after the last call to <see cref="Init"/>.
        /// </summary>
        public abstract void Reset();
    }
}
