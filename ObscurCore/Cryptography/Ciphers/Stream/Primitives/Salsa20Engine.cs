using System;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	/**
	* Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
	*/
	public class Salsa20Engine : IStreamCipher, ICsprngCompatible
	{
		/** Constants */
		private const int STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes

		private readonly static byte[]
			Sigma = Strings.ToAsciiByteArray("expand 32-byte k"),
            Tau = Strings.ToAsciiByteArray("expand 16-byte k");

		/*
		* variables to hold the state of the engine
		* during encryption and decryption
		*/
		private int		_index;
		private readonly int[]	_engineState = new int[STATE_SIZE]; // state
		private readonly int[]	_x = new int[STATE_SIZE] ; // internal buffer
		private readonly byte[]	_keyStream   = new byte[STATE_SIZE * 4];

	    private byte[]	// expanded state, 64 bytes
						_workingKey,
						_workingIv;

	    private bool	_initialised;

		/*
		* internal counter
		*/
		private int _cW0, _cW1, _cW2;

		/**
		* initialise a Salsa20 cipher.
		*
		* @param forEncryption whether or not we are for encryption.
		* @param params the parameters required to set up the cipher.
		* @exception ArgumentException if the params argument is
		* inappropriate.
		*/
		public void Init(
			bool				forEncryption, 
			ICipherParameters	parameters)
		{
			/* 
			* Salsa20 encryption and decryption is completely
			* symmetrical, so the 'forEncryption' is 
			* irrelevant. (Like 90% of stream ciphers)
			*/

			var ivParams = parameters as ParametersWithIV;

			if (ivParams == null)
				throw new ArgumentException("Salsa20 Init requires an IV", "parameters");

			byte[] iv = ivParams.GetIV();

			if (iv == null || iv.Length != 8)
				throw new ArgumentException("Salsa20 requires exactly 8 bytes of IV");

			var key = ivParams.Parameters as KeyParameter;

			if (key == null)
				throw new ArgumentException("Salsa20 Init requires a key", "parameters");

			_workingKey = key.GetKey();
			_workingIv = iv;

			setKey(_workingKey, _workingIv);
		}

		public string AlgorithmName
		{
			get { return "Salsa20"; }
		}

		public int StateSize
		{
			get { return 64; }
		}

		public byte ReturnByte(
			byte input)
		{
			if (limitExceeded())
			{
				throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
			}

			if (_index == 0)
			{
				salsa20WordToByte(_engineState, _keyStream);
				_engineState[8]++;
				if (_engineState[8] == 0)
				{
					_engineState[9]++;
				}
			}
			var output = (byte)(_keyStream[_index]^input);
			_index = (_index + 1) & 63;
	    
			return output;
		}

		public void ProcessBytes(
			byte[]	inBytes, 
			int		inOff, 
			int		len, 
			byte[]	outBytes, 
			int		outOff)
		{
			if (!_initialised)
			{
				throw new InvalidOperationException(AlgorithmName + " not initialised");
			}

			if ((inOff + len) > inBytes.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + len) > outBytes.Length)
			{
				throw new DataLengthException("output buffer too short");
			}
	        
			if (limitExceeded(len))
			{
				throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
			}

			for (int i = 0; i < len; i++)
			{
				if (_index == 0)
				{
					salsa20WordToByte(_engineState, _keyStream);
					_engineState[8]++;
					if (_engineState[8] == 0)
					{
						_engineState[9]++;
					}
				}
				outBytes[i+outOff] = (byte)(_keyStream[_index]^inBytes[i+inOff]);
				_index = (_index + 1) & 63;
			}
		}

        public void GetKeystream(byte[] buffer, int offset, int length) { 
            for (int i = 0; i < length; i++)
			{
				if (_index == 0)
				{
					salsa20WordToByte(_engineState, _keyStream);
					_engineState[8]++;
					if (_engineState[8] == 0)
					{
						_engineState[9]++;
					}
				}
				buffer[i+offset] = _keyStream[_index];
				_index = (_index + 1) & 63;
			}
        }

		public void Reset()
		{
			setKey(_workingKey, _workingIv);
		}

		// Private implementation

		private void setKey(byte[] keyBytes, byte[] ivBytes)
		{
			_workingKey = keyBytes;
			_workingIv  = ivBytes;

			_index = 0;
			resetCounter();
			int offset = 0;
			byte[] constants;

			// Key
			_engineState[1] = byteToIntLittle(_workingKey, 0);
			_engineState[2] = byteToIntLittle(_workingKey, 4);
			_engineState[3] = byteToIntLittle(_workingKey, 8);
			_engineState[4] = byteToIntLittle(_workingKey, 12);

			if (_workingKey.Length == 32)
			{
				constants = Sigma;
				offset = 16;
			}
			else
			{
				constants = Tau;
			}
	        
			_engineState[11] = byteToIntLittle(_workingKey, offset);
			_engineState[12] = byteToIntLittle(_workingKey, offset+4);
			_engineState[13] = byteToIntLittle(_workingKey, offset+8);
			_engineState[14] = byteToIntLittle(_workingKey, offset+12);
			_engineState[0 ] = byteToIntLittle(constants, 0);
			_engineState[5 ] = byteToIntLittle(constants, 4);
			_engineState[10] = byteToIntLittle(constants, 8);
			_engineState[15] = byteToIntLittle(constants, 12);
	        
			// IV
			_engineState[6] = byteToIntLittle(_workingIv, 0);
			_engineState[7] = byteToIntLittle(_workingIv, 4);
			_engineState[8] = _engineState[9] = 0;
	        
			_initialised = true;
		}
	    
		/**
		* Salsa20 function
		*
		* @param   input   input data
		*
		* @return  keystream
		*/    
		private void salsa20WordToByte(
			int[]	input,
			byte[]	output)
		{
			Array.Copy(input, 0, _x, 0, input.Length);

			for (int i = 0; i < 10; i++)
			{
				_x[ 4] ^= rotl((_x[ 0]+_x[12]), 7);
				_x[ 8] ^= rotl((_x[ 4]+_x[ 0]), 9);
				_x[12] ^= rotl((_x[ 8]+_x[ 4]),13);
				_x[ 0] ^= rotl((_x[12]+_x[ 8]),18);
				_x[ 9] ^= rotl((_x[ 5]+_x[ 1]), 7);
				_x[13] ^= rotl((_x[ 9]+_x[ 5]), 9);
				_x[ 1] ^= rotl((_x[13]+_x[ 9]),13);
				_x[ 5] ^= rotl((_x[ 1]+_x[13]),18);
				_x[14] ^= rotl((_x[10]+_x[ 6]), 7);
				_x[ 2] ^= rotl((_x[14]+_x[10]), 9);
				_x[ 6] ^= rotl((_x[ 2]+_x[14]),13);
				_x[10] ^= rotl((_x[ 6]+_x[ 2]),18);
				_x[ 3] ^= rotl((_x[15]+_x[11]), 7);
				_x[ 7] ^= rotl((_x[ 3]+_x[15]), 9);
				_x[11] ^= rotl((_x[ 7]+_x[ 3]),13);
				_x[15] ^= rotl((_x[11]+_x[ 7]),18);
				_x[ 1] ^= rotl((_x[ 0]+_x[ 3]), 7);
				_x[ 2] ^= rotl((_x[ 1]+_x[ 0]), 9);
				_x[ 3] ^= rotl((_x[ 2]+_x[ 1]),13);
				_x[ 0] ^= rotl((_x[ 3]+_x[ 2]),18);
				_x[ 6] ^= rotl((_x[ 5]+_x[ 4]), 7);
				_x[ 7] ^= rotl((_x[ 6]+_x[ 5]), 9);
				_x[ 4] ^= rotl((_x[ 7]+_x[ 6]),13);
				_x[ 5] ^= rotl((_x[ 4]+_x[ 7]),18);
				_x[11] ^= rotl((_x[10]+_x[ 9]), 7);
				_x[ 8] ^= rotl((_x[11]+_x[10]), 9);
				_x[ 9] ^= rotl((_x[ 8]+_x[11]),13);
				_x[10] ^= rotl((_x[ 9]+_x[ 8]),18);
				_x[12] ^= rotl((_x[15]+_x[14]), 7);
				_x[13] ^= rotl((_x[12]+_x[15]), 9);
				_x[14] ^= rotl((_x[13]+_x[12]),13);
				_x[15] ^= rotl((_x[14]+_x[13]),18);
			}

			int offset = 0;
			for (int i = 0; i < STATE_SIZE; i++)
			{
				intToByteLittle(_x[i] + input[i], output, offset);
				offset += 4;
			}

			for (int i = STATE_SIZE; i < _x.Length; i++)
			{
				intToByteLittle(_x[i], output, offset);
				offset += 4;
			}
		}

		// parallellise this by making x a array of arrays (number = no of cpus or # of cpus wanted to parallellise to)

		/**
		* 32 bit word to 4 byte array in little endian order
		*
		* @param   x   value to 'unpack'
		*
		* @return  value of x expressed as a byte[] array in little endian order
		*/
        //private byte[] intToByteLittle(
        //    int		x,
        //    byte[]	bs,
        //    int		off)
        //{
        //    bs[off] = (byte)x;
        //    bs[off + 1] = (byte)(x >> 8);
        //    bs[off + 2] = (byte)(x >> 16);
        //    bs[off + 3] = (byte)(x >> 24);
        //    return bs;
        //}

        private static void intToByteLittle(
			int		x,
			byte[]	bs,
			int		off)
		{
			bs[off] = (byte)x;
			bs[off + 1] = (byte)(x >> 8);
			bs[off + 2] = (byte)(x >> 16);
			bs[off + 3] = (byte)(x >> 24);
		}



		/**
		* Rotate left
		*
		* @param   x   value to rotate
		* @param   y   amount to rotate x
		*
		* @return  rotated x
		*/
		private static int rotl(
			int	x,
			int	y)
		{
			return (x << y) | ((int)((uint) x >> -y));
		}

		/**
		* Pack byte[] array into an int in little endian order
		*
		* @param   x       byte array to 'pack'
		* @param   offset  only x[offset]..x[offset+3] will be packed
		*
		* @return  x[offset]..x[offset+3] 'packed' into an int in little-endian order
		*/
		private static int byteToIntLittle(
			byte[]	x,
			int		offset)
		{
			return ((x[offset] & 255)) |
				((x[offset + 1] & 255) <<  8) |
				((x[offset + 2] & 255) << 16) |
				(x[offset + 3] << 24);
		}

		private void resetCounter()
		{
			_cW0 = 0;
			_cW1 = 0;
			_cW2 = 0;
		}

		private bool limitExceeded()
		{
			_cW0++;
			if (_cW0 == 0)
			{
				_cW1++;
				if (_cW1 == 0)
				{
					_cW2++;
					return (_cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
				}
			}

			return false;
		}

		/*
		 * this relies on the fact len will always be positive.
		 */
		private bool limitExceeded(
			int len)
		{
			if (_cW0 >= 0)
			{
				_cW0 += len;
			}
			else
			{
				_cW0 += len;
				if (_cW0 >= 0)
				{
					_cW1++;
					if (_cW1 == 0)
					{
						_cW2++;
						return (_cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
					}
				}
			}

			return false;
		}
	}
}
