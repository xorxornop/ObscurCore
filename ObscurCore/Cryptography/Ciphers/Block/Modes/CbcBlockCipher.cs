using System;
using PerfCopy;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
    /// <summary>
    /// Cipher block-chaining mode of operation for block ciphers.
    /// </summary>
    public class CbcBlockCipher
        : BlockCipherModeBase
    {
        private byte[] _cbcV, _cbcNextV;

        public CbcBlockCipher(BlockCipherBase cipher)
            : base(BlockCipherMode.Cbc, cipher)
        {
            this._cbcV = new byte[CipherBlockSize];
            this._cbcNextV = new byte[CipherBlockSize];
        }

        /// <inheritdoc />
        protected override void InitState(byte[] key)
        {
            BlockCipher.Init(Encrypting, key);
            Reset();
        }

        /// <inheritdoc />
        internal override int ProcessBlockInternal(byte[] input, int inOff, byte[] output, int outOff)
        {
            return (Encrypting)
                ? EncryptBlock(input, inOff, output, outOff)
                : DecryptBlock(input, inOff, output, outOff);
        }

        /// <summary>
        /// Reset the cipher to the same state as it was after the last init (if there was one).
        /// </summary>
        public override void Reset()
        {
            if (IV != null) {
                Array.Copy(IV, 0, _cbcV, 0, IV.Length);
            }          
            _cbcNextV.SecureWipe();

            BlockCipher.Reset();
        }

        private int EncryptBlock(
            byte[] input,
            int inOff,
            byte[] outBytes,
            int outOff)
        {
            /*
            * XOR the cbcV and the input,
            * then encrypt the cbcV
            */
            _cbcV.XorInPlaceInternal(0, input, inOff, CipherBlockSize);

            int length = BlockCipher.ProcessBlock(_cbcV, 0, outBytes, outOff);

            /*
            * copy ciphertext to cbcV
            */
            outBytes.DeepCopy_NoChecks(outOff, _cbcV, 0, _cbcV.Length);

            return length;
        }

        private int DecryptBlock(
            byte[] input,
            int inOff,
            byte[] outBytes,
            int outOff)
        {
            input.DeepCopy_NoChecks(inOff, _cbcNextV, 0, CipherBlockSize);

            int length = BlockCipher.ProcessBlock(input, inOff, outBytes, outOff);

            /*
            * XOR the cbcV and the output
            */
            outBytes.XorInPlaceInternal(outOff, _cbcV, 0, CipherBlockSize);

            /*
            * swap the back up buffer into next position
            */
            byte[] tmp;

            tmp = _cbcV;
            _cbcV = _cbcNextV;
            _cbcNextV = tmp;

            return length;
        }
    }
}
