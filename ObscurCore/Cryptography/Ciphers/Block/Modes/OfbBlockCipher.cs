using System;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
	/// <summary>
	/// Implements Output FeedBack (OFB) mode on top of a block cipher.
	/// </summary>
	public class OfbBlockCipher : BlockCipherModeBase
    {
		private readonly byte[]			_ofbV;
		private readonly byte[]			_ofbOutV;

        public OfbBlockCipher(BlockCipherBase cipher)
            : base(BlockCipherMode.Ofb, cipher)
        {
            this._ofbV = new byte[CipherBlockSize];
            this._ofbOutV = new byte[CipherBlockSize];
        }

        /// <inheritdoc />
        protected override void InitState(byte[] key)
        {
            // Prepend the supplied IV with zeros (as per FIPS PUB 81)
            byte[] workingIv = new byte[CipherBlockSize];
            IV.CopyBytes(0, workingIv, CipherBlockSize - IV.Length, IV.Length);
            Array.Clear(workingIv, 0, CipherBlockSize - IV.Length);
            IV = workingIv;

            Reset();
            BlockCipher.Init(true, key); // Streaming mode - cipher always used in encryption mode
        }

        /// <inheritdoc />
	    internal override int ProcessBlockInternal(byte[] input, int inOff, byte[] output, int outOff)
	    {
            BlockCipher.ProcessBlock(_ofbV, 0, _ofbOutV, 0);

            // XOR the ofbV with the plaintext producing the cipher text (and
            // the next input block).
            input.XorInternal(inOff, _ofbOutV, 0, output, outOff, CipherBlockSize);

            // change over the input block.
            Array.Copy(_ofbV, CipherBlockSize, _ofbV, 0, _ofbV.Length - CipherBlockSize);
            Array.Copy(_ofbOutV, 0, _ofbV, _ofbV.Length - CipherBlockSize, CipherBlockSize);

            return CipherBlockSize;
	    }

        /// <summary>
        ///     Reset the chaining vector back to the IV and reset the underlying cipher.
        /// </summary>
		public override void Reset() {
            Array.Copy(IV, 0, _ofbV, 0, IV.Length);
            BlockCipher.Reset();
        }
    }

}
