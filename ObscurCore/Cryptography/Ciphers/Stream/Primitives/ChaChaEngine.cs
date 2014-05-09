using System;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	/// <summary>
	/// Implementation of Daniel J. Bernstein's ChaCha stream cipher.
	/// </summary>
	public class ChaChaEngine : IStreamCipher, ICsprngCompatible
	{
        /* Constants */
        private const int STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes
        protected const int STRIDE_SIZE = STATE_SIZE * 4;
        protected const int DEFAULT_ROUNDS = 20;

		private const string CipherName = "ChaCha";

        protected readonly static byte[]
            Sigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k"),
            Tau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");

        /* Variables */
        protected readonly int rounds;
        protected bool initialised;
        private int index;
        protected readonly uint[] engineState = new uint[STATE_SIZE]; // state
        protected readonly uint[] x = new uint[STATE_SIZE]; // internal buffer
        private readonly byte[] keyStream = new byte[STATE_SIZE * 4];

        private uint cW0, cW1, cW2;

		/// <summary>
		/// Creates a 20 round ChaCha engine.
		/// </summary>
		public ChaChaEngine() : this(DEFAULT_ROUNDS)
		{
		}

		/// <summary>
		/// Creates a ChaCha engine with a specific number of rounds.
		/// </summary>
		/// <param name="rounds">the number of rounds (must be an even number).</param>
		public ChaChaEngine(int rounds)
		{
            if (rounds <= 0 || (rounds & 1) != 0) {
                throw new ArgumentException("'rounds' must be a positive, even number.");
            }

            this.rounds = rounds;
		}

        public void Init(bool encrypting, byte[] key, byte[] iv)
        {
            if (iv == null)
                throw new ArgumentNullException("iv", "ChaCha initialisation requires an IV.");
            else if (iv.Length != 8)
                throw new ArgumentException("ChaCha requires 8 bytes of IV.", "iv");

            if (key == null)
                throw new ArgumentNullException("key", "ChaCha initialisation requires a key.");
            else if (key.Length != 16 && key.Length != 32) {
                throw new ArgumentException("ChaCha requires a 16 or 32 byte key");
            }

            SetKey(key, iv);
            Reset();
            initialised = true;
        }

        protected int NonceSize
        {
            get { return 8; }
        }

        public virtual string AlgorithmName
        {
            get {
                if (rounds != DEFAULT_ROUNDS) 
                    return CipherName + rounds;
                else return CipherName;
            }
        }

        public int StateSize
        {
            get { return 64; }
        }

        public byte ReturnByte(
            byte input)
        {
            if (LimitExceeded()) {
                throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
            }

            if (index == 0) {
                GenerateKeyStream(keyStream, 0);
                AdvanceCounter();
            }

            byte output = (byte)(keyStream[index] ^ input);
            index = (index + 1) & 63;

            return output;
        }

		protected void AdvanceCounter() {
			if (++engineState[12] == 0) {
				++engineState[13];
			}
		}

        public void ProcessBytes(
            byte[] inBytes,
            int inOff,
            int len,
            byte[] outBytes,
            int outOff)
        {
            if (!initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
            if ((inOff + len) > inBytes.Length)
                throw new ArgumentException("Input buffer too short.");
            if ((outOff + len) > outBytes.Length)
                throw new ArgumentException("Output buffer too short.");

            if (LimitExceeded((uint)len)) {
                throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
            }

            if (len < 1)
                return;

            // Any left over from last time?
            if (index > 0) {
                var blen = STRIDE_SIZE - index;
                if (blen > len)
                    blen = len;
                inBytes.Xor(inOff, keyStream, index, outBytes, outOff, blen);
                index += blen;
                inOff += blen;
                outOff += blen;
                len -= blen;
            }

            int remainder;
            var blocks = Math.DivRem(len, STRIDE_SIZE, out remainder);

            for (var i = 0; i < blocks; i++) {
                GenerateKeyStream(keyStream, 0);
                AdvanceCounter();
                inBytes.Xor(inOff, keyStream, 0, outBytes, outOff, STRIDE_SIZE);
                inOff += STRIDE_SIZE;
                outOff += STRIDE_SIZE;
            }

            if (remainder > 0) {
                GenerateKeyStream(keyStream, 0);
                AdvanceCounter();
                inBytes.Xor(inOff, keyStream, 0, outBytes, outOff, remainder);
            }
            index = remainder;
        }

        public void GetKeystream(byte[] buffer, int offset, int length)
        {
            if (index > 0) {
                var blen = STRIDE_SIZE - index;
                if (blen > length)
                    blen = length;
                keyStream.CopyBytes(index, buffer, offset, blen);
                index += blen;
                offset += blen;
                length -= blen;
            }
            while (length > 0) {
                if (length >= STRIDE_SIZE) {
                    GenerateKeyStream(buffer, offset);
                    AdvanceCounter();
                    offset += STRIDE_SIZE;
                    length -= STRIDE_SIZE;
                } else {
                    GenerateKeyStream(keyStream, 0);
                    AdvanceCounter();
                    keyStream.CopyBytes(0, buffer, offset, length);
                    index = length;
                    length = 0;
                }
            }
        }

        public void Reset()
        {
            index = 0;
            ResetLimitCounter();
            ResetCounter();
        }

		protected void ResetCounter() {
			engineState[12] = engineState[13] = 0;
		}

		protected void SetKey(byte[] keyBytes, byte[] ivBytes) {
			int offset = 0;
			byte[] constants;

			// Key
			engineState[4] = Pack.LE_To_UInt32(keyBytes, 0);
			engineState[5] = Pack.LE_To_UInt32(keyBytes, 4);
			engineState[6] = Pack.LE_To_UInt32(keyBytes, 8);
			engineState[7] = Pack.LE_To_UInt32(keyBytes, 12);

			if (keyBytes.Length == 32) {
				constants = Sigma;
				offset = 16;
			} else {
				constants = Tau;
			}

			engineState[8] = Pack.LE_To_UInt32(keyBytes, offset);
			engineState[9] = Pack.LE_To_UInt32(keyBytes, offset + 4);
			engineState[10] = Pack.LE_To_UInt32(keyBytes, offset + 8);
			engineState[11] = Pack.LE_To_UInt32(keyBytes, offset + 12);

			engineState[0] = Pack.LE_To_UInt32(constants, 0);
			engineState[1] = Pack.LE_To_UInt32(constants, 4);
			engineState[2] = Pack.LE_To_UInt32(constants, 8);
			engineState[3] = Pack.LE_To_UInt32(constants, 12);

			// Counter
			engineState[12] = engineState[13] = 0;

			// IV
			engineState[14] = Pack.LE_To_UInt32(ivBytes, 0);
			engineState[15] = Pack.LE_To_UInt32(ivBytes, 4);
		}

		protected void GenerateKeyStream(byte[] output, int offset)
		{
			ChaChaCoreNoChecks(rounds, engineState, x);
			Pack.UInt32_To_LE(x, output, offset);
		}

		/// <summary>
		/// ChaCha function.
		/// </summary>
		/// <param name="rounds">The number of ChaCha rounds to execute</param>
		/// <param name="input">The input words.</param>
		/// <param name="x">The ChaCha state to modify.</param>
		internal static void ChaChaCore(int rounds, uint[] input, uint[] x) {
			if (input.Length != 16) {
				throw new ArgumentException("Incorrect length (not 16).", "input");
			} else if (x.Length != 16) {
				throw new ArgumentException("Incorrect length (not 16).", "x");
			}
			if (rounds % 2 != 0) {
				throw new ArgumentException("Number of rounds must be even");
			}

			ChaChaCoreNoChecks (rounds, input, x);
		}

		private static void ChaChaCoreNoChecks(int rounds, uint[] input, uint[] x) {
			uint x00 = input[ 0];
			uint x01 = input[ 1];
			uint x02 = input[ 2];
			uint x03 = input[ 3];
			uint x04 = input[ 4];
			uint x05 = input[ 5];
			uint x06 = input[ 6];
			uint x07 = input[ 7];
			uint x08 = input[ 8];
			uint x09 = input[ 9];
			uint x10 = input[10];
			uint x11 = input[11];
			uint x12 = input[12];
			uint x13 = input[13];
			uint x14 = input[14];
			uint x15 = input[15];

			for (int i = rounds; i > 0; i -= 2) {
				x00 += x04; x12 = R(x12 ^ x00, 16);
				x08 += x12; x04 = R(x04 ^ x08, 12);
				x00 += x04; x12 = R(x12 ^ x00, 8);
				x08 += x12; x04 = R(x04 ^ x08, 7);
				x01 += x05; x13 = R(x13 ^ x01, 16);
				x09 += x13; x05 = R(x05 ^ x09, 12);
				x01 += x05; x13 = R(x13 ^ x01, 8);
				x09 += x13; x05 = R(x05 ^ x09, 7);
				x02 += x06; x14 = R(x14 ^ x02, 16);
				x10 += x14; x06 = R(x06 ^ x10, 12);
				x02 += x06; x14 = R(x14 ^ x02, 8);
				x10 += x14; x06 = R(x06 ^ x10, 7);
				x03 += x07; x15 = R(x15 ^ x03, 16);
				x11 += x15; x07 = R(x07 ^ x11, 12);
				x03 += x07; x15 = R(x15 ^ x03, 8);
				x11 += x15; x07 = R(x07 ^ x11, 7);
				x00 += x05; x15 = R(x15 ^ x00, 16);
				x10 += x15; x05 = R(x05 ^ x10, 12);
				x00 += x05; x15 = R(x15 ^ x00, 8);
				x10 += x15; x05 = R(x05 ^ x10, 7);
				x01 += x06; x12 = R(x12 ^ x01, 16);
				x11 += x12; x06 = R(x06 ^ x11, 12);
				x01 += x06; x12 = R(x12 ^ x01, 8);
				x11 += x12; x06 = R(x06 ^ x11, 7);
				x02 += x07; x13 = R(x13 ^ x02, 16);
				x08 += x13; x07 = R(x07 ^ x08, 12);
				x02 += x07; x13 = R(x13 ^ x02, 8);
				x08 += x13; x07 = R(x07 ^ x08, 7);
				x03 += x04; x14 = R(x14 ^ x03, 16);
				x09 += x14; x04 = R(x04 ^ x09, 12);
				x03 += x04; x14 = R(x14 ^ x03, 8);
				x09 += x14; x04 = R(x04 ^ x09, 7);
			}

			x[ 0] = x00 + input[ 0];
			x[ 1] = x01 + input[ 1];
			x[ 2] = x02 + input[ 2];
			x[ 3] = x03 + input[ 3];
			x[ 4] = x04 + input[ 4];
			x[ 5] = x05 + input[ 5];
			x[ 6] = x06 + input[ 6];
			x[ 7] = x07 + input[ 7];
			x[ 8] = x08 + input[ 8];
			x[ 9] = x09 + input[ 9];
			x[10] = x10 + input[10];
			x[11] = x11 + input[11];
			x[12] = x12 + input[12];
			x[13] = x13 + input[13];
			x[14] = x14 + input[14];
			x[15] = x15 + input[15];
		}

        internal static uint R(uint x, int y)
        {
            return (x << y) | (x >> (32 - y));
        }

        private void ResetLimitCounter()
        {
            cW0 = 0;
            cW1 = 0;
            cW2 = 0;
        }
        private bool LimitExceeded()
        {
            if (++cW0 == 0) {
                if (++cW1 == 0) {
                    return (++cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
                }
            }

            return false;
        }

        private bool LimitExceeded(uint len)
        {
            uint old = cW0;
            cW0 += len;
            if (cW0 < old) {
                if (++cW1 == 0) {
                    return (++cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
                }
            }

            return false;
        }
	}
}
