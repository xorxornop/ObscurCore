using System;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
	/// <summary>
	/// Implements Output FeedBack (OFB) mode on top of a block cipher.
	/// </summary>
	public class OfbBlockCipher : IBlockCipher
    {
		private readonly byte[]			_iv;
		private readonly byte[]			_ofbV;
		private readonly byte[]			_ofbOutV;
		private readonly int			_blockSize;
		private readonly IBlockCipher	_cipher;


		public OfbBlockCipher(IBlockCipher cipher)
        {
            this._cipher = cipher;
			//this.blockSize = blockSize / 8; //truncated length was removed from specification, parameter removed accordingly
			this._blockSize = cipher.BlockSize; // full length feedback
            this._iv = new byte[cipher.BlockSize];
            this._ofbV = new byte[cipher.BlockSize];
            this._ofbOutV = new byte[cipher.BlockSize];
        }

        public IBlockCipher UnderlyingCipher {
            get { return _cipher; }
        }


		/// <summary>
		/// Initialise the cipher. 
		/// If a supplied IV is short, it is handled in FIPS fashion.
		/// </summary>
		/// <param name="encrypting">If set to <c>true</c> encrypting.</param>
		/// <param name="key">Key for the cipher.</param>
		/// <param name="iv">Initialisation vector for the cipher mode.</param>
		public void Init (bool encrypting, byte[] key, byte[] iv) {
			if(iv.IsNullOrZeroLength()) {
				throw new ArgumentException ("OFB block cipher mode requires an initialisation vector for security.");
			}

			// Prepend the supplied IV with zeros (as per FIPS PUB 81)
			Array.Copy(iv, 0, _iv, _iv.Length - iv.Length, iv.Length);
			Array.Clear(_iv, 0, _iv.Length - iv.Length);
			Reset();
			_cipher.Init (true, key, null); // Streaming mode - cipher always used in encryption mode
		}

        public string AlgorithmName
        {
            get { return _cipher.AlgorithmName + "/OFB" + (_blockSize * 8); }
        }

		public bool IsPartialBlockOkay
		{
			get { return true; }
		}

        public int BlockSize {
            get { return _blockSize; }
        }

		public int ProcessBlock(byte[] input, int inOff, byte[] output, int	outOff) {
			if ((inOff + _blockSize) > input.Length) {
                throw new DataLengthException("input buffer too short");
            }

			if ((outOff + _blockSize) > output.Length) {
                throw new DataLengthException("output buffer too short");
            }

            _cipher.ProcessBlock(_ofbV, 0, _ofbOutV, 0);

            // XOR the ofbV with the plaintext producing the cipher text (and
            // the next input block).
			for (int i = 0; i < _blockSize; i++) {
                output[outOff + i] = (byte)(_ofbOutV[i] ^ input[inOff + i]);
            }

            // change over the input block.
            Array.Copy(_ofbV, _blockSize, _ofbV, 0, _ofbV.Length - _blockSize);
            Array.Copy(_ofbOutV, 0, _ofbV, _ofbV.Length - _blockSize, _blockSize);

            return _blockSize;
        }

        /**
        * reset the feedback vector back to the IV and reset the underlying
        * cipher.
        */
		public void Reset() {
            Array.Copy(_iv, 0, _ofbV, 0, _iv.Length);
            _cipher.Reset();
        }
    }

}
