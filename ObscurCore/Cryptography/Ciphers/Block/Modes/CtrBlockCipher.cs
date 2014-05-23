using System;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
	/// <summary>
	/// Implements Output FeedBack (OFB; also called Segmented Integer Counter, SIC) mode on top of a block cipher.
	/// </summary>
	public class CtrBlockCipher : IBlockCipher
	{
		private readonly IBlockCipher 	_cipher;
		private readonly int 		_blockSize;
		private readonly byte[] 	_iv;
		private readonly byte[] 	_counter;
		private readonly byte[] 	_counterOut;

		public CtrBlockCipher(IBlockCipher cipher)
		{
			this._cipher = cipher;
			this._blockSize = _cipher.BlockSize;
			this._iv = new byte[_blockSize];
			this._counter = new byte[_blockSize];
			this._counterOut = new byte[_blockSize];
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
			if (iv.IsNullOrZeroLength()) {
				throw new ArgumentException ("CTR/SIC block cipher mode requires an initialisation vector for security.");
			}

			// Prepend the supplied IV with zeros (as per FIPS PUB 81)
			iv.CopyBytes(0, _iv, _iv.Length - iv.Length, iv.Length);
			Array.Clear(_iv, 0, _iv.Length - iv.Length);
			Reset();
			_cipher.Init(true, key, null); // Streaming mode - cipher always used in encryption mode
		}

		public string AlgorithmName
		{
			get { return _cipher.AlgorithmName + "/CTR"; }
		}

		public bool IsPartialBlockOkay
		{
			get { return true; }
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
			_cipher.ProcessBlock(_counter, 0, _counterOut, 0);

			// XOR the counterOut with the plaintext producing the cipher text
			input.XorInternal(inOff, _counterOut, 0, output, outOff, _blockSize);

			// Increment the counter
			int j = _blockSize;
			while (--j >= 0 && ++_counter[j] == 0) { }

			return _blockSize;
		}

		public void Reset()
		{
            _iv.CopyBytes(0, _counter, 0, _blockSize);
			_cipher.Reset();
		}
	}
}
