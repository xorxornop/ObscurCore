using System;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support;

using ObscurCore.Extensions.BitPacking;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	/**
	* Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
	*/
	public class Salsa20Engine : IStreamCipher, ICsprngCompatible
	{
		/** Constants */
		private const int STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes
		protected const int DEFAULT_ROUNDS = 20;
		private const string CIPHER_NAME = "Salsa20";

		private readonly static byte[]
			Sigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k"),
			Tau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");

		/*
		* variables to hold the state of the engine
		* during encryption and decryption
		*/
		private int					_index;
		protected readonly int[]	_engineState 	= new int[STATE_SIZE]; // state
		private readonly int[]		_x 				= new int[STATE_SIZE] ; // internal buffer
		private readonly byte[]		_keyStream   	= new byte[STATE_SIZE * 4];

		protected readonly int 		_rounds;

	    private byte[]	// expanded state, 64 bytes
						_workingKey,
						_workingIv;

	    private bool	_initialised;

		/*
		* internal counter
		*/
		private int _cW0, _cW1, _cW2;

		public Salsa20Engine (int rounds = DEFAULT_ROUNDS)
		{
			if (rounds < 2 || rounds % 2 != 0) {
				throw new ArgumentException ("Rounds must be an even number greater or equal to 2.");
			}
			_rounds = rounds;
		}


		public virtual void Init (bool encrypting, byte[] key, byte[] iv) {
			if (iv == null) 
				throw new ArgumentNullException("iv", "Salsa20 initialisation requires an IV.");
			if (iv.Length != 8)
				throw new ArgumentException("Salsa20 requires exactly 8 bytes of IV.", "iv");

			if (key == null) 
				throw new ArgumentNullException("key", "Salsa20 initialisation requires a key.");
			else if (key.Length != 16 && key.Length != 32) {
				throw new ArgumentException ("Salsa20 requires a 16 or 32 byte key.", "key");
			}

			SetKey(key, iv);
		}

		public string AlgorithmName
		{
			get { 
				if(_rounds == DEFAULT_ROUNDS) {
					return CIPHER_NAME;
				} else {
					return "Salsa20/" + _rounds;
				}
			}
		}

		public int StateSize
		{
			get { return 64; }
		}

		public byte ReturnByte(
			byte input)
		{
			if (IsLimitExceeded())
			{
				throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
			}

			if (_index == 0)
			{
				Salsa20WordToByte(_engineState, _keyStream);
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

		public void ProcessBytes(byte[] inBytes, int inOff, int len, byte[]	outBytes, int outOff) {
			if (!_initialised) {
				throw new InvalidOperationException (AlgorithmName + " not initialised");
			} else if ((inOff + len) > inBytes.Length) {
				throw new DataLengthException ("input buffer too short");
			} else if ((outOff + len) > outBytes.Length) {
				throw new DataLengthException ("output buffer too short");
			}
	        
			if (IsLimitExceeded (len)) {
				throw new MaxBytesExceededException ("2^70 byte limit per IV would be exceeded; Change IV");
			}

			for (int i = 0; i < len; i++) {
				if (_index == 0) {
					Salsa20WordToByte (_engineState, _keyStream);
					_engineState [8]++;
					if (_engineState [8] == 0) {
						_engineState [9]++;
					}
				}
				outBytes[i + outOff] = (byte)(_keyStream[_index] ^ inBytes[i + inOff]);
				_index = (_index + 1) & 63;
			}
		}

        public void GetKeystream(byte[] buffer, int offset, int length) { 
			for (int i = 0; i < length; i++) {
				if (_index == 0) {
					Salsa20WordToByte(_engineState, _keyStream);
					_engineState[8]++;
					if (_engineState[8] == 0) {
						_engineState[9]++;
					}
				}
				buffer[i+offset] = _keyStream[_index];
				_index = (_index + 1) & 63;
			}
        }

		public void Reset () {
			SetKey(_workingKey, _workingIv);
		}

		// Private implementation

		protected virtual void SetKey (byte[] keyBytes, byte[] ivBytes) {
			_workingKey = keyBytes;
			_workingIv  = ivBytes;

			_index = 0;
			ResetCounter();
			int offset = 0;
			byte[] constants;

			// Key
			_engineState[1] = _workingKey.LittleEndianToInt32 (0);
			_engineState[2] = _workingKey.LittleEndianToInt32 (4);
			_engineState[3] = _workingKey.LittleEndianToInt32 (8);
			_engineState[4] = _workingKey.LittleEndianToInt32 (12);

			if (_workingKey.Length == 32) {
				constants = Sigma;
				offset = 16;
			} else {
				constants = Tau;
			}

			_engineState[11] = _workingKey.LittleEndianToInt32 (offset + 0);
			_engineState[12] = _workingKey.LittleEndianToInt32 (offset + 4);
			_engineState[13] = _workingKey.LittleEndianToInt32 (offset + 8);
			_engineState[14] = _workingKey.LittleEndianToInt32 (offset + 12);
			_engineState[0 ] = constants.LittleEndianToInt32 (0);
			_engineState[5 ] = constants.LittleEndianToInt32 (4);
			_engineState[10] = constants.LittleEndianToInt32 (8);
			_engineState[15] = constants.LittleEndianToInt32 (12);
	        
			// IV
			_engineState[6] = _workingIv.LittleEndianToInt32 (0);
			_engineState[7] = _workingIv.LittleEndianToInt32 (4);
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
		private void Salsa20WordToByte (int[] input, byte[] output) {
			int x0 = input[0];
			int x1 = input[1];
			int x2 = input[2];
			int x3 = input[3];
			int x4 = input[4];
			int x5 = input[5];
			int x6 = input[6];
			int x7 = input[7];
			int x8 = input[8];
			int x9 = input[9];
			int x10 = input[10];
			int x11 = input[11];
			int x12 = input[12];
			int x13 = input[13];
			int x14 = input[14];
			int x15 = input[15];

			for (int i = 0; i < _rounds; i+= 2) {
				x4  ^= RotLeft(x0  + x12, 7);
				x8  ^= RotLeft(x4  + x0,  9);
				x12 ^= RotLeft(x8  + x4,  13);
				x0  ^= RotLeft(x12 + x8,  18);
				x9  ^= RotLeft(x5  + x1,  7);
				x13 ^= RotLeft(x9  + x5,  9);
				x1  ^= RotLeft(x13 + x9,  13);
				x5  ^= RotLeft(x1  + x13, 18);
				x14 ^= RotLeft(x10 + x6,  7);
				x2  ^= RotLeft(x14 + x10, 9);
				x6  ^= RotLeft(x2  + x14, 13);
				x10 ^= RotLeft(x6  + x2,  18);
				x3  ^= RotLeft(x15 + x11, 7);
				x7  ^= RotLeft(x3  + x15, 9);
				x11 ^= RotLeft(x7  + x3,  13);
				x15 ^= RotLeft(x11 + x7,  18);

				x1  ^= RotLeft(x0  + x3,  7);
				x2  ^= RotLeft(x1  + x0,  9);
				x3  ^= RotLeft(x2  + x1,  13);
				x0  ^= RotLeft(x3  + x2,  18);
				x6  ^= RotLeft(x5  + x4,  7);
				x7  ^= RotLeft(x6  + x5,  9);
				x4  ^= RotLeft(x7  + x6,  13);
				x5  ^= RotLeft(x4  + x7,  18);
				x11 ^= RotLeft(x10 + x9,  7);
				x8  ^= RotLeft(x11 + x10, 9);
				x9  ^= RotLeft(x8  + x11, 13);
				x10 ^= RotLeft(x9  + x8,  18);
				x12 ^= RotLeft(x15 + x14, 7);
				x13 ^= RotLeft(x12 + x15, 9);
				x14 ^= RotLeft(x13 + x12, 13);
				x15 ^= RotLeft(x14 + x13, 18);
			}

			(x0 +  input[0 ]).ToLittleEndian (output, 0 );
			(x1 +  input[1 ]).ToLittleEndian (output, 4 );
			(x2 +  input[2 ]).ToLittleEndian (output, 8 );
			(x3 +  input[3 ]).ToLittleEndian (output, 12);
			(x4 +  input[4 ]).ToLittleEndian (output, 16);
			(x5 +  input[5 ]).ToLittleEndian (output, 20);
			(x6 +  input[6 ]).ToLittleEndian (output, 24);
			(x7 +  input[7 ]).ToLittleEndian (output, 28);
			(x8 +  input[8 ]).ToLittleEndian (output, 32);
			(x9 +  input[9 ]).ToLittleEndian (output, 36);
			(x10 + input[10]).ToLittleEndian (output, 40);
			(x11 + input[11]).ToLittleEndian (output, 44);
			(x12 + input[12]).ToLittleEndian (output, 48);
			(x13 + input[13]).ToLittleEndian (output, 52);
			(x14 + input[14]).ToLittleEndian (output, 56);
			(x15 + input[15]).ToLittleEndian (output, 60);
		}

		protected void SalsaCore (int rounds, int[] input, int[] output) {
			int x0 = input[0];
			int x1 = input[1];
			int x2 = input[2];
			int x3 = input[3];
			int x4 = input[4];
			int x5 = input[5];
			int x6 = input[6];
			int x7 = input[7];
			int x8 = input[8];
			int x9 = input[9];
			int x10 = input[10];
			int x11 = input[11];
			int x12 = input[12];
			int x13 = input[13];
			int x14 = input[14];
			int x15 = input[15];

			for (int i = 0; i < rounds; i+= 2) {
				x4  ^= RotLeft(x0  + x12, 7);
				x8  ^= RotLeft(x4  + x0,  9);
				x12 ^= RotLeft(x8  + x4,  13);
				x0  ^= RotLeft(x12 + x8,  18);
				x9  ^= RotLeft(x5  + x1,  7);
				x13 ^= RotLeft(x9  + x5,  9);
				x1  ^= RotLeft(x13 + x9,  13);
				x5  ^= RotLeft(x1  + x13, 18);
				x14 ^= RotLeft(x10 + x6,  7);
				x2  ^= RotLeft(x14 + x10, 9);
				x6  ^= RotLeft(x2  + x14, 13);
				x10 ^= RotLeft(x6  + x2,  18);
				x3  ^= RotLeft(x15 + x11, 7);
				x7  ^= RotLeft(x3  + x15, 9);
				x11 ^= RotLeft(x7  + x3,  13);
				x15 ^= RotLeft(x11 + x7,  18);

				x1  ^= RotLeft(x0  + x3,  7);
				x2  ^= RotLeft(x1  + x0,  9);
				x3  ^= RotLeft(x2  + x1,  13);
				x0  ^= RotLeft(x3  + x2,  18);
				x6  ^= RotLeft(x5  + x4,  7);
				x7  ^= RotLeft(x6  + x5,  9);
				x4  ^= RotLeft(x7  + x6,  13);
				x5  ^= RotLeft(x4  + x7,  18);
				x11 ^= RotLeft(x10 + x9,  7);
				x8  ^= RotLeft(x11 + x10, 9);
				x9  ^= RotLeft(x8  + x11, 13);
				x10 ^= RotLeft(x9  + x8,  18);
				x12 ^= RotLeft(x15 + x14, 7);
				x13 ^= RotLeft(x12 + x15, 9);
				x14 ^= RotLeft(x13 + x12, 13);
				x15 ^= RotLeft(x14 + x13, 18);
			}

			output [0]  = x0  + input [0];
			output [1]  = x1  + input [1];
			output [2]  = x2  + input [2];
			output [3]  = x3  + input [3];
			output [4]  = x4  + input [4];
			output [5]  = x5  + input [5];
			output [6]  = x6  + input [6];
			output [7]  = x7  + input [7];
			output [8]  = x8  + input [8];
			output [9]  = x9  + input [9];
			output [10] = x10 + input [10];
			output [11] = x11 + input [11];
			output [12] = x12 + input [12];
			output [13] = x13 + input [13];
			output [14] = x14 + input [14];
			output [15] = x15 + input [15];
		}
        

		private static int RotLeft(int a, int b) { 
			return (a << b) | ((int)((uint) a >> -b));
		}

		private void ResetCounter () {
			_cW0 = 0;
			_cW1 = 0;
			_cW2 = 0;
		}

		private bool IsLimitExceeded () {
			_cW0++;
			if (_cW0 == 0) {
				_cW1++;
				if (_cW1 == 0) {
					_cW2++;
					return (_cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
				}
			}

			return false;
		}

		/*
		 * this relies on the fact len will always be positive.
		 */
		private bool IsLimitExceeded (int len) {
			if (_cW0 >= 0) {
				_cW0 += len;
			} else {
				_cW0 += len;
				if (_cW0 >= 0) {
					_cW1++;
					if (_cW1 == 0) {
						_cW2++;
						return (_cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
					}
				}
			}

			return false;
		}
	}
}
