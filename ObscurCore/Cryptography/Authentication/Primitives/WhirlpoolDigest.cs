using System;
using System.Diagnostics;
using BitManipulator;
using PerfCopy;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
    class WhirlpoolDigest : IHash
    {
        #region Consts

        private const int BlockSizeBytes = 64;
        private const int ROUNDS = 10;
        private const uint REDUCTION_POLYNOMIAL = 0x011D;

        private static readonly uint[] s_SBOX =
        {
            0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
            0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
            0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
            0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
            0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
            0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
            0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
            0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
            0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
            0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
            0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
            0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
            0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
            0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
            0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
            0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
        };

        private static readonly ulong[] s_C0 = new ulong[256];
        private static readonly ulong[] s_C1 = new ulong[256];
        private static readonly ulong[] s_C2 = new ulong[256];
        private static readonly ulong[] s_C3 = new ulong[256];
        private static readonly ulong[] s_C4 = new ulong[256];
        private static readonly ulong[] s_C5 = new ulong[256];
        private static readonly ulong[] s_C6 = new ulong[256];
        private static readonly ulong[] s_C7 = new ulong[256];

        private static ulong[] s_rc = new ulong[ROUNDS + 1];

        private static readonly short[] EIGHT = new short[BITCOUNT_ARRAY_SIZE];

        static WhirlpoolDigest()
        {
            EIGHT[BITCOUNT_ARRAY_SIZE - 1] = 8;

            for (int i = 0; i < 256; i++)
            {
                uint v1 = s_SBOX[i];
                uint v2 = maskWithReductionPolynomial(v1 << 1);
                uint v4 = maskWithReductionPolynomial(v2 << 1);
                uint v5 = v4 ^ v1;
                uint v8 = maskWithReductionPolynomial(v4 << 1);
                uint v9 = v8 ^ v1;

                s_C0[i] = packIntoULong(v1, v1, v4, v1, v8, v5, v2, v9);
                s_C1[i] = packIntoULong(v9, v1, v1, v4, v1, v8, v5, v2);
                s_C2[i] = packIntoULong(v2, v9, v1, v1, v4, v1, v8, v5);
                s_C3[i] = packIntoULong(v5, v2, v9, v1, v1, v4, v1, v8);
                s_C4[i] = packIntoULong(v8, v5, v2, v9, v1, v1, v4, v1);
                s_C5[i] = packIntoULong(v1, v8, v5, v2, v9, v1, v1, v4);
                s_C6[i] = packIntoULong(v4, v1, v8, v5, v2, v9, v1, v1);
                s_C7[i] = packIntoULong(v1, v4, v1, v8, v5, v2, v9, v1);
            }

            s_rc[0] = 0UL;

            for (int r = 1; r <= ROUNDS; r++)
            {
                int i = 8 * (r - 1);
                s_rc[r] = (s_C0[i] & 0xff00000000000000UL) ^
                    (s_C1[i + 1] & 0x00ff000000000000UL) ^
                    (s_C2[i + 2] & 0x0000ff0000000000UL) ^
                    (s_C3[i + 3] & 0x000000ff00000000UL) ^
                    (s_C4[i + 4] & 0x00000000ff000000UL) ^
                    (s_C5[i + 5] & 0x0000000000ff0000UL) ^
                    (s_C6[i + 6] & 0x000000000000ff00UL) ^
                    (s_C7[i + 7] & 0x00000000000000ffUL);
            }

        }

        private static ulong packIntoULong(uint b7, uint b6, uint b5, uint b4, uint b3, uint b2, uint b1, uint b0)
        {
            return ((ulong)b7 << 56) ^
                   ((ulong)b6 << 48) ^
                   ((ulong)b5 << 40) ^
                   ((ulong)b4 << 32) ^
                   ((ulong)b3 << 24) ^
                   ((ulong)b2 << 16) ^
                   ((ulong)b1 << 8) ^
                   b0;
        }

        private static uint maskWithReductionPolynomial(uint input)
        {
            if (input >= 0x100)
                input ^= REDUCTION_POLYNOMIAL;
            return input;
        }

        #endregion


        private const int BITCOUNT_ARRAY_SIZE = 32;
        private byte[] _buffer = new byte[BlockSizeBytes];
        private int _bufferFilled;
        private short[] _bitCount = new short[BITCOUNT_ARRAY_SIZE];

        // -- internal hash state --
        private ulong[] _hash = new ulong[8];
        private ulong[] _K = new ulong[8]; // the round key
        private ulong[] _L = new ulong[8];
        private ulong[] _block = new ulong[8]; // mu (buffer)
        private ulong[] _state = new ulong[8]; // the current "cipher" state

        public WhirlpoolDigest()
        {
        }

        public string AlgorithmName
        {
            get { return "Whirlpool"; }
        }

        /// <summary>
        ///     Enumerated function identity.
        /// </summary>
        public HashFunction Identity { get { return HashFunction.Whirlpool; } }

        public int OutputSize
        {
            get { return 64; }
        }

        public int StateSize
        {
            get { return BlockSizeBytes; }
        }

        public void Update(byte input)
        {
            _buffer[_bufferFilled++] = input;

            if (_bufferFilled == _buffer.Length) {
                processFilledBuffer();
            }

            increment();
        }

        private void increment()
        {
            int carry = 0;
            for (int i = _bitCount.Length - 1; i >= 0; i--) {
                int sum = (_bitCount[i] & 0xff) + EIGHT[i] + carry;

                carry = sum >> 8;
                _bitCount[i] = (short)(sum & 0xff);
            }
        }

        private void processFilledBuffer()
        {
            // copies into the block...
            _buffer.BigEndianToUInt64_NoChecks(0, _block, 0, _block.Length);
            processBlock();
            _bufferFilled = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
        }

        private void processFilledBuffer(byte[] buffer, int offset)
        {
            // copies into the block...
            //buffer.BigEndianToUInt64_NoChecks(offset, _block, 0, _block.Length);
            for (int i = 0; i < _state.Length; i++) {
                _block[i] = bytesToLongFromBuffer(_buffer, i * 8);
            }
            processBlock();
            _bufferFilled = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
        }

        private static ulong bytesToLongFromBuffer(byte[] buffer, int startPos)
        {
            ulong rv = (((buffer[startPos + 0] & 0xffUL) << 56) |
                ((buffer[startPos + 1] & 0xffUL) << 48) |
                ((buffer[startPos + 2] & 0xffUL) << 40) |
                ((buffer[startPos + 3] & 0xffUL) << 32) |
                ((buffer[startPos + 4] & 0xffUL) << 24) |
                ((buffer[startPos + 5] & 0xffUL) << 16) |
                ((buffer[startPos + 6] & 0xffUL) << 8) |
                ((buffer[startPos + 7]) & 0xffUL));

            return rv;
        }

        public void BlockUpdate(byte[] input, int inOff, int len) {

            int offset = inOff;
            int count = len;
            int bufferRemaining = BlockSizeBytes - _bufferFilled;
			
			if ((_bufferFilled > 0) && (count > bufferRemaining))
			{
                input.DeepCopy_NoChecks(offset, _buffer, _bufferFilled, bufferRemaining);
                processFilledBuffer();
				offset += bufferRemaining;
				count -= bufferRemaining;
				_bufferFilled = 0;
			}
			
			while (count >= BlockSizeBytes)
			{
				processFilledBuffer(input, offset);
				offset += BlockSizeBytes;
				count -= BlockSizeBytes;
			}
			
			if (count > 0)
			{
                input.DeepCopy_NoChecks(offset, _buffer, _bufferFilled, count);
				_bufferFilled += count;
			}
        }
        private void processBlock()
		{
			// buffer contents have been transferred to the _block[] array via
			// processFilledBuffer

			// compute and apply K^0
			for (int i = 0; i < 8; i++)
			{
				_state[i] = _block[i] ^ (_K[i] = _hash[i]);
			}

			// iterate over the rounds
			for (int round = 1; round <= ROUNDS; round++)
			{
				for (int i = 0; i < 8; i++)
				{
					_L[i] = 0;
					_L[i] ^= s_C0[(int)(_K[(i - 0) & 7] >> 56) & 0xff];
					_L[i] ^= s_C0[(int)(_K[(i - 1) & 7] >> 48) & 0xff];
					_L[i] ^= s_C0[(int)(_K[(i - 2) & 7] >> 40) & 0xff];
					_L[i] ^= s_C0[(int)(_K[(i - 3) & 7] >> 32) & 0xff];
					_L[i] ^= s_C0[(int)(_K[(i - 4) & 7] >> 24) & 0xff];
					_L[i] ^= s_C0[(int)(_K[(i - 5) & 7] >> 16) & 0xff];
					_L[i] ^= s_C0[(int)(_K[(i - 6) & 7] >>  8) & 0xff];
					_L[i] ^= s_C0[(int)(_K[(i - 7) & 7]) & 0xff];
				}

				Array.Copy(_L, 0, _K, 0, _K.Length);

				_K[0] ^= s_rc[round];

				// apply the round transformation
				for (int i = 0; i < 8; i++)
				{
					_L[i] = _K[i];

					_L[i] ^= s_C0[(int)(_state[(i - 0) & 7] >> 56) & 0xff];
					_L[i] ^= s_C0[(int)(_state[(i - 1) & 7] >> 48) & 0xff];
					_L[i] ^= s_C0[(int)(_state[(i - 2) & 7] >> 40) & 0xff];
					_L[i] ^= s_C0[(int)(_state[(i - 3) & 7] >> 32) & 0xff];
					_L[i] ^= s_C0[(int)(_state[(i - 4) & 7] >> 24) & 0xff];
					_L[i] ^= s_C0[(int)(_state[(i - 5) & 7] >> 16) & 0xff];
					_L[i] ^= s_C0[(int)(_state[(i - 6) & 7] >> 8) & 0xff];
					_L[i] ^= s_C0[(int)(_state[(i - 7) & 7]) & 0xff];
				}

				// save the current state
				Array.Copy(_L, 0, _state, 0, _state.Length);
			}

			// apply Miuaguchi-Preneel compression
			for (int i = 0; i < 8; i++)
			{
				_hash[i] ^= _state[i] ^ _block[i];
			}

		}

        public int DoFinal(byte[] output, int outOff)
        {
            finish();

            //_hash.ToBigEndian_NoChecks(0, output, outOff, _hash.Length);
            for (int i = 0; i < 8; i++) {
                convertLongToByteArray(_hash[i], output, outOff + (i * 8));
            }

            Reset();

            return OutputSize;
        }

        private static void convertLongToByteArray(ulong inputLong, byte[] outputArray, int offSet)
        {
            for (int i = 0; i < 8; i++) {
                outputArray[offSet + i] = (byte)((inputLong >> (56 - (i * 8))) & 0xff);
            }
        }

        private void finish()
        {
            /*
                * this makes a copy of the current bit length. at the expense of an
                * object creation of 32 bytes rather than providing a _stopCounting
                * boolean which was the alternative I could think of.
                */
            byte[] bitLength = copyBitLength();

            _buffer[_bufferFilled++] |= 0x80;

            if (_bufferFilled == _buffer.Length) {
                processFilledBuffer();
            }

            /*
                * Final block contains
                * [ ... data .... ][0][0][0][ length ]
                *
                * if [ length ] cannot fit.  Need to create a new block.
                */
            if (_bufferFilled > 32) {
                while (_bufferFilled != 0) {
                    Update((byte)0);
                }
            }

            while (_bufferFilled <= 32) {
                Update((byte)0);
            }

            // copy the length information to the final 32 bytes of the
            // 64 byte block....
            Array.Copy(bitLength, 0, _buffer, 32, bitLength.Length);

            processFilledBuffer();
        }

        private byte[] copyBitLength()
        {
            byte[] rv = new byte[BITCOUNT_ARRAY_SIZE];
            for (int i = 0; i < rv.Length; i++) {
                rv[i] = (byte)(_bitCount[i] & 0xff);
            }
            return rv;
        }

        public void Reset()
        {
            _buffer.SecureWipe();
            _bufferFilled = 0;
        }
    }
}
