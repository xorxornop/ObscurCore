using System;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
    /**
    * implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
    */
    public class CbcBlockCipher
		: IBlockCipher
    {
		private bool					_encrypting;
		private byte[] 					_cbcV;
		private byte[]					_cbcNextV;

		private readonly byte[]			_iv;
		private readonly int			_blockSize;
		private readonly IBlockCipher	_cipher;
        

        public CbcBlockCipher(IBlockCipher cipher)
        {
            this._cipher = cipher;
            this._blockSize = cipher.BlockSize;
            this._iv = new byte[_blockSize];
            this._cbcV = new byte[_blockSize];
            this._cbcNextV = new byte[_blockSize];
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
				throw new ArgumentException ("CBC block cipher mode requires an initialisation vector for security.");
			}

			this._encrypting = encrypting;
			// Prepend the supplied IV with zeros (as per FIPS PUB 81)
			Array.Copy(iv, 0, _iv, _iv.Length - iv.Length, iv.Length);
			Array.Clear(_iv, 0, _iv.Length - iv.Length);
			Reset();
			_cipher.Init (encrypting, key, null); // Streaming mode - cipher always used in encryption mode
		}

        public string AlgorithmName
        {
            get { return _cipher.AlgorithmName + "/CBC"; }
        }

		public bool IsPartialBlockOkay
		{
			get { return false; }
		}

        public int BlockSize {
			get { return _blockSize; }
        }

        public int ProcessBlock(
            byte[]	input,
            int		inOff,
            byte[]	output,
            int		outOff)
        {
            return (_encrypting)
				?	EncryptBlock(input, inOff, output, outOff)
				:	DecryptBlock(input, inOff, output, outOff);
        }

		/// <summary>
		/// Reset the cipher to the same state as it was after the last init (if there was one).
		/// </summary>
        public void Reset()
        {
            Array.Copy(_iv, 0, _cbcV, 0, _iv.Length);
			_cbcNextV.SecureWipe();

            _cipher.Reset();
        }

        /**
        * Do the appropriate chaining step for CBC mode encryption.
        *
        * @param in the array containing the data to be encrypted.
        * @param inOff offset into the in array the data starts at.
        * @param out the array the encrypted data will be copied into.
        * @param outOff the offset into the out array the output will start at.
        * @exception DataLengthException if there isn't enough data in in, or
        * space in out.
        * @exception InvalidOperationException if the cipher isn't initialised.
        * @return the number of bytes processed and produced.
        */
        private int EncryptBlock(
            byte[]      input,
            int         inOff,
            byte[]      outBytes,
            int         outOff)
        {
            if ((inOff + _blockSize) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }

            /*
            * XOR the cbcV and the input,
            * then encrypt the cbcV
            */
			_cbcV.XorInPlaceInternal(0, input, inOff, _blockSize);

            int length = _cipher.ProcessBlock(_cbcV, 0, outBytes, outOff);

            /*
            * copy ciphertext to cbcV
            */
			outBytes.CopyBytes(outOff, _cbcV, 0, _cbcV.Length);

            return length;
        }

        /**
        * Do the appropriate chaining step for CBC mode decryption.
        *
        * @param in the array containing the data to be decrypted.
        * @param inOff offset into the in array the data starts at.
        * @param out the array the decrypted data will be copied into.
        * @param outOff the offset into the out array the output will start at.
        * @exception DataLengthException if there isn't enough data in in, or
        * space in out.
        * @exception InvalidOperationException if the cipher isn't initialised.
        * @return the number of bytes processed and produced.
        */
        private int DecryptBlock(
            byte[]      input,
            int         inOff,
            byte[]      outBytes,
            int         outOff)
        {
            if ((inOff + _blockSize) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }

			input.CopyBytes(inOff, _cbcNextV, 0, _blockSize);

            int length = _cipher.ProcessBlock(input, inOff, outBytes, outOff);

            /*
            * XOR the cbcV and the output
            */
			outBytes.XorInPlaceInternal(outOff, _cbcV, 0, _blockSize);

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
