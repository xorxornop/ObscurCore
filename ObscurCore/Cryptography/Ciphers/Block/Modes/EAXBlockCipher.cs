using System;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Authentication.Primitives;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
	/**
	* A Two-Pass Authenticated-Encryption Scheme Optimized for Simplicity and 
	* Efficiency - by M. Bellare, P. Rogaway, D. Wagner.
	* 
	* http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
	* 
	* EAX is an AEAD scheme based on CTR and OMAC1/CMAC, that uses a single block 
	* cipher to encrypt and authenticate data. It's on-line (the length of a 
	* message isn't needed to begin processing it), has good performances, it's
	* simple and provably secure (provided the underlying block cipher is secure).
	* 
	* Of course, this implementations is NOT thread-safe.
	*/
	public class EaxBlockCipher
		: IAeadBlockCipher
	{
		private enum Tag : byte { N, H, C };

		private readonly SicBlockCipher _cipher;

		private bool _forEncryption;

		private readonly int _blockSize;

		private readonly IMac _mac;

		private readonly byte[] _nonceMac;
		private readonly byte[] _associatedTextMac;
		private readonly byte[] _macBlock;

		private int _macSize;
		private readonly byte[] _bufBlock;
		private int _bufOff;

		/**
		* Constructor that accepts an instance of a block cipher engine.
		*
		* @param cipher the engine to use
		*/
		public EaxBlockCipher(
			IBlockCipher cipher)
		{
			_blockSize = cipher.BlockSize;
			_mac = new CMac(cipher);
			_macBlock = new byte[_blockSize];
			_bufBlock = new byte[_blockSize * 2];
			_associatedTextMac = new byte[_mac.MacSize];
			_nonceMac = new byte[_mac.MacSize];
			this._cipher = new SicBlockCipher(cipher);
		}

		public virtual string AlgorithmName
		{
			get { return _cipher.UnderlyingCipher.AlgorithmName + "/EAX"; }
		}

	    public virtual int BlockSize {
	        get { return _cipher.BlockSize; }
	    }

	    public virtual void Init(
			bool				forEncryption,
			ICipherParameters	parameters)
		{
			this._forEncryption = forEncryption;

			byte[] nonce, associatedText;
			ICipherParameters keyParam;

	        var aeadParameters = parameters as AeadParameters;
	        if (aeadParameters != null)
			{
				nonce = aeadParameters.GetNonce();
				associatedText = aeadParameters.GetAssociatedText();
				_macSize = aeadParameters.MacSize / 8;
				keyParam = aeadParameters.Key;
			}
			else {
	            var iv = parameters as ParametersWithIV;
	            if (iv != null)
	            {
	                nonce = iv.GetIV();
	                associatedText = new byte[0];
	                _macSize = _mac.MacSize / 2;
	                keyParam = iv.Parameters;
	            }
	            else
	            {
	                throw new ArgumentException("invalid parameters passed to EAX");
	            }
	        }

	        byte[] tag = new byte[_blockSize];

			_mac.Init(keyParam);
			tag[_blockSize - 1] = (byte) Tag.H;
			_mac.BlockUpdate(tag, 0, _blockSize);
			_mac.BlockUpdate(associatedText, 0, associatedText.Length);
			_mac.DoFinal(_associatedTextMac, 0);

			tag[_blockSize - 1] = (byte) Tag.N;
			_mac.BlockUpdate(tag, 0, _blockSize);
			_mac.BlockUpdate(nonce, 0, nonce.Length);
			_mac.DoFinal(_nonceMac, 0);

			tag[_blockSize - 1] = (byte) Tag.C;
			_mac.BlockUpdate(tag, 0, _blockSize);

			_cipher.Init(true, new ParametersWithIV(keyParam, _nonceMac));
		}

		private void calculateMac()
		{
			byte[] outC = new byte[_blockSize];
			_mac.DoFinal(outC, 0);

			for (int i = 0; i < _macBlock.Length; i++)
			{
				_macBlock[i] = (byte)(_nonceMac[i] ^ _associatedTextMac[i] ^ outC[i]);
			}
		}

		public virtual void Reset()
		{
			Reset(true);
		}

		private void Reset(
			bool clearMac)
		{
			_cipher.Reset();
			_mac.Reset();

			_bufOff = 0;
			Array.Clear(_bufBlock, 0, _bufBlock.Length);

			if (clearMac)
			{
				Array.Clear(_macBlock, 0, _macBlock.Length);
			}

			byte[] tag = new byte[_blockSize];
			tag[_blockSize - 1] = (byte) Tag.C;
			_mac.BlockUpdate(tag, 0, _blockSize);
		}

		public virtual int ProcessByte(
			byte	input,
			byte[]	outBytes,
			int		outOff)
		{
			return process(input, outBytes, outOff);
		}

		public virtual int ProcessBytes(
			byte[]	inBytes,
			int		inOff,
			int		len,
			byte[]	outBytes,
			int		outOff)
		{
			int resultLen = 0;

			for (int i = 0; i != len; i++)
			{
				resultLen += process(inBytes[inOff + i], outBytes, outOff + resultLen);
			}

			return resultLen;
		}

		public virtual int DoFinal(
			byte[]	outBytes,
			int		outOff)
		{
			int extra = _bufOff;
			byte[] tmp = new byte[_bufBlock.Length];

			_bufOff = 0;

			if (_forEncryption)
			{
				_cipher.ProcessBlock(_bufBlock, 0, tmp, 0);
				_cipher.ProcessBlock(_bufBlock, _blockSize, tmp, _blockSize);

				Array.Copy(tmp, 0, outBytes, outOff, extra);

				_mac.BlockUpdate(tmp, 0, extra);

				calculateMac();

				Array.Copy(_macBlock, 0, outBytes, outOff + extra, _macSize);

				Reset(false);

				return extra + _macSize;
			}
			else
			{
				if (extra > _macSize)
				{
					_mac.BlockUpdate(_bufBlock, 0, extra - _macSize);

					_cipher.ProcessBlock(_bufBlock, 0, tmp, 0);
					_cipher.ProcessBlock(_bufBlock, _blockSize, tmp, _blockSize);

					Array.Copy(tmp, 0, outBytes, outOff, extra - _macSize);
				}

				calculateMac();

				if (!verifyMac(_bufBlock, extra - _macSize))
					throw new InvalidCipherTextException("mac check in EAX failed");

				Reset(false);

				return extra - _macSize;
			}
		}

		public virtual byte[] GetMac()
		{
			byte[] mac = new byte[_macSize];

			Array.Copy(_macBlock, 0, mac, 0, _macSize);

			return mac;
		}

		public virtual int GetUpdateOutputSize(
			int len)
		{
			return ((len + _bufOff) / _blockSize) * _blockSize;
		}

		public virtual int GetOutputSize(
			int len)
		{
			if (_forEncryption)
			{
				return len + _bufOff + _macSize;
			}

			return len + _bufOff - _macSize;
		}

		private int process(
			byte	b,
			byte[]	outBytes,
			int		outOff)
		{
			_bufBlock[_bufOff++] = b;

			if (_bufOff == _bufBlock.Length)
			{
				int size;

				if (_forEncryption)
				{
					size = _cipher.ProcessBlock(_bufBlock, 0, outBytes, outOff);

					_mac.BlockUpdate(outBytes, outOff, _blockSize);
				}
				else
				{
					_mac.BlockUpdate(_bufBlock, 0, _blockSize);

					size = _cipher.ProcessBlock(_bufBlock, 0, outBytes, outOff);
				}

				_bufOff = _blockSize;
				Array.Copy(_bufBlock, _blockSize, _bufBlock, 0, _blockSize);

				return size;
			}

			return 0;
		}

		private bool verifyMac(byte[] mac, int off)
		{
			for (int i = 0; i < _macSize; i++)
			{
				if (_macBlock[i] != mac[off + i])
				{
					return false;
				}
			}

			return true;
		}
	}
}
