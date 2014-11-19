using System;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Modes;
using ObscurCore.Cryptography.Ciphers.Block.Padding;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	/**
	* CMAC - as specified at www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
	* <p>
	* CMAC is analogous to OMAC1 - see also en.wikipedia.org/wiki/CMAC
	* </p><p>
	* CMAC is a NIST recomendation - see 
	* csrc.nist.gov/CryptoToolkit/modes/800-38_Series_Publications/SP800-38B.pdf
	* </p><p>
	* CMAC/OMAC1 is a blockcipher-based message authentication code designed and
	* analyzed by Tetsu Iwata and Kaoru Kurosawa.
	* </p><p>
	* CMAC/OMAC1 is a simple variant of the CBC MAC (Cipher Block Chaining Message 
	* Authentication Code). OMAC stands for One-Key CBC MAC.
	* </p><p>
	* It supports 128- or 64-bits block ciphers, with any key size, and returns
	* a MAC with dimension less or equal to the block size of the underlying 
	* cipher.
	* </p>
	*/
	public class CMac
		: IMac
	{
		private const byte Constant128 = (byte)0x87;
		private const byte Constant64 = (byte)0x1b;

		private readonly byte[] _nullCbcIv;
		private readonly byte[] _zeroes;
		private readonly byte[] _mac;
		private readonly byte[] _buf;
		private int _bufOff;

        private readonly CbcBlockCipher _cipher;
		private readonly int _outputSize;

		private byte[] L, Lu, Lu2;

		/**
		* create a standard MAC based on a CBC block cipher (64 or 128 bit block).
		* This will produce an authentication code the length of the block size
		* of the cipher.
		*
		* @param cipher the cipher to be used as the basis of the MAC generation.
		*/
		public CMac(
			BlockCipherBase cipher)
			: this(cipher, cipher.BlockSize * 8)
		{
		}

		/**
		* create a standard MAC based on a block cipher with the size of the
		* MAC been given in bits.
		* <p/>
		* Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
		* or 16 bits if being used as a data authenticator (FIPS Publication 113),
		* and in general should be less than the size of the block cipher as it reduces
		* the chance of an exhaustive attack (see Handbook of Applied Cryptography).
		*
		* @param cipher        the cipher to be used as the basis of the MAC generation.
		* @param macSizeInBits the size of the MAC in bits, must be a multiple of 8 and @lt;= 128.
		*/
		public CMac(
			BlockCipherBase	cipher,
			int				macSizeInBits)
		{
			if ((macSizeInBits % 8) != 0)
				throw new ArgumentException("MAC size must be multiple of 8");

			if (macSizeInBits > (cipher.BlockSize * 8))
			{
				throw new ArgumentException(
					"MAC size must be less or equal to "
						+ (cipher.BlockSize * 8));
			}

			if (cipher.BlockSize != 8 && cipher.BlockSize != 16)
			{
				throw new ArgumentException(
					"Block size must be either 64 or 128 bits");
			}

			this._cipher = new CbcBlockCipher(cipher);
			this._outputSize = macSizeInBits / 8;

			_zeroes = new byte[cipher.BlockSize];
			_nullCbcIv = new byte[cipher.BlockSize];

			_buf = new byte[cipher.BlockSize];
			_bufOff = 0;

			_mac = new byte[this._outputSize];
		}

	    /// <summary>
	    ///     Enumerated function identity.
	    /// </summary>
	    public MacFunction Identity { get { return MacFunction.Cmac; } }

	    public string AlgorithmName
		{
			get { return _cipher.AlgorithmName + "/CMAC"; }
		}

		private static int ShiftLeft(byte[] block, byte[] output)
		{
			int i = block.Length;
			uint bit = 0;
			while (--i >= 0)
			{
				uint b = block[i];
				output[i] = (byte)((b << 1) | bit);
				bit = (b >> 7) & 1;
			}
			return (int)bit;
		}

		private static byte[] doubleLu(
			byte[] inBytes)
		{
			byte[] ret = new byte[inBytes.Length];
			int carry = ShiftLeft(inBytes, ret);
			int xor = inBytes.Length == 16 ? Constant128 : Constant64;

			/*			
             * NOTE: This construction is an attempt at a constant-time implementation.
             */
			ret[inBytes.Length - 1] ^= (byte)(xor >> ((1 - carry) << 3));

			return ret;
		}

		public void Init (byte[] key) {
			Reset();

			_cipher.Init (true, key, _nullCbcIv);

			//initializes the L, Lu, Lu2 numbers
			L = new byte[_zeroes.Length];
			_cipher.ProcessBlock(_zeroes, 0, L, 0);
			Lu = doubleLu(L);
			Lu2 = doubleLu(Lu);

			_cipher.Init (true, key, _nullCbcIv);
		}

	    public int OutputSize {
	        get { return _outputSize; }
	    }

	    public void Update(
			byte input)
		{
			if (_bufOff == _buf.Length)
			{
				_cipher.ProcessBlock(_buf, 0, _mac, 0);
				_bufOff = 0;
			}

			_buf[_bufOff++] = input;
		}

		public void BlockUpdate(
			byte[]	inBytes,
			int		inOff,
			int		len)
		{
			if (len < 0)
				throw new ArgumentException("Can't have a negative input length!");

			int blockSize = _cipher.BlockSize;
			int gapLen = blockSize - _bufOff;

			if (len > gapLen)
			{
				Array.Copy(inBytes, inOff, _buf, _bufOff, gapLen);

				_cipher.ProcessBlock(_buf, 0, _mac, 0);

				_bufOff = 0;
				len -= gapLen;
				inOff += gapLen;

				while (len > blockSize)
				{
					_cipher.ProcessBlock(inBytes, inOff, _mac, 0);

					len -= blockSize;
					inOff += blockSize;
				}
			}

			Array.Copy(inBytes, inOff, _buf, _bufOff, len);

			_bufOff += len;
		}

		public int DoFinal(
			byte[]	outBytes,
			int		outOff)
		{
			int blockSize = _cipher.BlockSize;

			byte[] lu;
			if (_bufOff == blockSize)
			{
				lu = Lu;
			}
			else
			{
				new Iso7816D4Padding().AddPadding(_buf, _bufOff);
				lu = Lu2;
			}

			for (int i = 0; i < _mac.Length; i++)
			{
				_buf[i] ^= lu[i];
			}

			_cipher.ProcessBlock(_buf, 0, _mac, 0);

			Array.Copy(_mac, 0, outBytes, outOff, _outputSize);

			Reset();

			return _outputSize;
		}

		/**
		* Reset the mac generator.
		*/
		public void Reset()
		{
			/*
			* clean the buffer.
			*/
			Array.Clear(_buf, 0, _buf.Length);
			_bufOff = 0;

			// Make sure all IV bytes are zeroed
			Array.Clear(_nullCbcIv, 0, _nullCbcIv.Length);

			/*
			* Reset the underlying cipher.
			*/
			_cipher.Reset();
		}
	}
}
