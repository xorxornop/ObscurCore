using System;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
	/// <summary>
	/// Implements Cipher FeedBack (CFB) mode on top of a block cipher. 
	/// Supports variable feedback size, default is 8 bits (1 byte).
	/// </summary>
	public class CfbBlockCipher : IBlockCipher
    {
		private bool					encrypting;
		private readonly byte[]			_iv;
		private readonly byte[]			_cfbV;
		private readonly byte[]			_cfbOutV;
		private readonly int			_feedbackSize;
		private readonly IBlockCipher	_cipher;

		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.Cryptography.Ciphers.Block.Modes.CfbBlockCipher"/> class.
		/// </summary>
		/// <param name="cipher">Cipher to be used as the basis for the feedback mode.</param>
		/// <param name="feedbackSize">
		/// Bytes copied in feedback mechanism per block. 
		/// Defaults to full block, but other values can be used to produce a self-synchonising 
		/// stream cipher such as with CFB-8 (1 byte feedback - slow).
		/// </param>
		public CfbBlockCipher (IBlockCipher cipher, int? feedbackSize = null)
        {
            this._cipher = cipher;
			this._feedbackSize = feedbackSize ?? cipher.BlockSize;
            this._iv = new byte[cipher.BlockSize];
            this._cfbV = new byte[cipher.BlockSize];
            this._cfbOutV = new byte[cipher.BlockSize];
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
				throw new ArgumentException ("CFB block cipher mode requires an initialisation vector for security.");
			}

			this.encrypting = encrypting;
			// Prepend the supplied IV with zeros (as per FIPS PUB 81)
			Array.Copy(iv, 0, _iv, _iv.Length - iv.Length, iv.Length);
			Array.Clear(_iv, 0, _iv.Length - iv.Length);
			Reset();
			_cipher.Init (true, key, null); // Streaming mode - cipher always used in encryption mode
		}

        public string AlgorithmName
        {
			get { return _cipher.AlgorithmName + "/CFB-" + _feedbackSize; }
        }

		public bool IsPartialBlockOkay
		{
			get { return true; }
		}

        public int BlockSize {
            get { return _feedbackSize; }
        }


        public int ProcessBlock(
            byte[]	input,
            int		inOff,
            byte[]	output,
            int		outOff)
        {
            return (encrypting)
				?	EncryptBlock(input, inOff, output, outOff)
				:	DecryptBlock(input, inOff, output, outOff);
        }

        public int EncryptBlock(
            byte[]      input,
            int         inOff,
            byte[]      outBytes,
            int         outOff)
        {
            if ((inOff + _feedbackSize) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            if ((outOff + _feedbackSize) > outBytes.Length)
            {
                throw new DataLengthException("output buffer too short");
            }
            _cipher.ProcessBlock(_cfbV, 0, _cfbOutV, 0);
            //
            // XOR the cfbV with the plaintext producing the ciphertext
            //
            for (int i = 0; i < _feedbackSize; i++)
            {
                outBytes[outOff + i] = (byte)(_cfbOutV[i] ^ input[inOff + i]);
            }
            //
            // change over the input block.
            //
            Array.Copy(_cfbV, _feedbackSize, _cfbV, 0, _cfbV.Length - _feedbackSize);
            Array.Copy(outBytes, outOff, _cfbV, _cfbV.Length - _feedbackSize, _feedbackSize);
            return _feedbackSize;
        }
        
        public int DecryptBlock(
            byte[]	input,
            int		inOff,
            byte[]	outBytes,
            int		outOff)
        {
            if ((inOff + _feedbackSize) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            if ((outOff + _feedbackSize) > outBytes.Length)
            {
                throw new DataLengthException("output buffer too short");
            }
            _cipher.ProcessBlock(_cfbV, 0, _cfbOutV, 0);
            //
            // change over the input block.
            //
            Array.Copy(_cfbV, _feedbackSize, _cfbV, 0, _cfbV.Length - _feedbackSize);
            Array.Copy(input, inOff, _cfbV, _cfbV.Length - _feedbackSize, _feedbackSize);
            //
            // XOR the cfbV with the ciphertext producing the plaintext
            //
            for (int i = 0; i < _feedbackSize; i++)
            {
                outBytes[outOff + i] = (byte)(_cfbOutV[i] ^ input[inOff + i]);
            }
            return _feedbackSize;
        }
        
		/// <summary>
		/// Reset the chaining vector back to the IV and reset the underlying cipher.
		/// </summary>
        public void Reset()
        {
            Array.Copy(_iv, 0, _cfbV, 0, _iv.Length);
            _cipher.Reset();
        }
    }
}
