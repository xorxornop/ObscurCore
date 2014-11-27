using System;
using PerfCopy;

namespace Obscur.Core.Cryptography.Ciphers.Block.Modes
{
    /// <summary>
    /// Implements Cipher FeedBack (CFB) mode on top of a block cipher. 
    /// Supports variable feedback size - default is full block.
    /// </summary>
    public class CfbBlockCipher : BlockCipherModeBase
    {
        private readonly byte[] _cfbV;
        private readonly byte[] _cfbOutV;
        private readonly int _feedbackSize;

        /// <summary>
        /// Instantiates a CFB mode block cipher wrapper.
        /// </summary>
        /// <param name="cipher">Cipher to be used as the basis for the feedback mode.</param>
        /// <param name="feedbackSize">
        /// Bytes copied in feedback mechanism per block. 
        /// Defaults to full block, but other values can be used to produce a self-synchronising 
        /// stream cipher, such as CFB-8 (1 byte feedback - slow).
        /// </param>
        public CfbBlockCipher(BlockCipherBase cipher, int? feedbackSize = null)
            : base(BlockCipherMode.Cfb, cipher)
        {
            _feedbackSize = feedbackSize ?? cipher.BlockSize;
            _cfbV = new byte[cipher.BlockSize];
            _cfbOutV = new byte[cipher.BlockSize];
        }

        public int FeedbackSize
        {
            get { return _feedbackSize; }
        }

        /// <inheritdoc />
        protected override void InitState(byte[] key)
        {
            // Prepend the supplied IV with zeros (as per FIPS PUB 81)
            byte[] workingIv = new byte[CipherBlockSize];
            IV.CopyBytes_NoChecks(0, workingIv, CipherBlockSize - IV.Length, IV.Length);
            Array.Clear(workingIv, 0, CipherBlockSize - IV.Length);
            IV = workingIv;

            Reset();
            BlockCipher.Init(true, key); // Streaming mode - cipher always used in encryption mode
        }

        /// <inheritdoc />
        internal override int ProcessBlockInternal(byte[] input, int inOff, byte[] output, int outOff)
        {
            return (Encrypting)
                ? EncryptBlock(input, inOff, output, outOff)
                : DecryptBlock(input, inOff, output, outOff);
        }

        private int EncryptBlock(
            byte[] input,
            int inOff,
            byte[] outBytes,
            int outOff)
        {
            BlockCipher.ProcessBlock(_cfbV, 0, _cfbOutV, 0);
            // XOR the cfbV with the plaintext producing the ciphertext
            input.XorInternal(inOff, _cfbOutV, 0, outBytes, outOff, _feedbackSize);
            // change over the input block.
            Array.Copy(_cfbV, _feedbackSize, _cfbV, 0, _cfbV.Length - _feedbackSize);
            Array.Copy(outBytes, outOff, _cfbV, _cfbV.Length - _feedbackSize, _feedbackSize);
            return _feedbackSize;
        }

        private int DecryptBlock(
            byte[] input,
            int inOff,
            byte[] outBytes,
            int outOff)
        {
            BlockCipher.ProcessBlock(_cfbV, 0, _cfbOutV, 0);
            // change over the input block.
            Array.Copy(_cfbV, _feedbackSize, _cfbV, 0, _cfbV.Length - _feedbackSize);
            Array.Copy(input, inOff, _cfbV, _cfbV.Length - _feedbackSize, _feedbackSize);
            // XOR the cfbV with the ciphertext producing the plaintext
            input.XorInternal(inOff, _cfbOutV, 0, outBytes, outOff, _feedbackSize);

            return _feedbackSize;
        }

        /// <summary>
        ///     Reset the chaining vector back to the IV and reset the underlying cipher.
        /// </summary>
        public override void Reset()
        {
            Array.Copy(IV, 0, _cfbV, 0, IV.Length);
            _cfbOutV.SecureWipe();

            BlockCipher.Reset();
        }
    }
}
