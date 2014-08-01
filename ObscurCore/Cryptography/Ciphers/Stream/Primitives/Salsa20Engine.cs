using System;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
    /// <summary>
    /// Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
    /// </summary>
    public class Salsa20Engine : StreamCipherEngine, ICsprngCompatible
    {
        /* Constants */
        private const int EngineStateSize = 16; // 16, 32 bit ints = 64 bytes
        protected const int StrideSize = EngineStateSize * 4;
        protected const int DefaultRounds = 20;
        protected string CipherName = "Salsa20";

        protected static readonly byte[]
            Sigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k"),
            Tau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");

        /* Variables */
        protected readonly int Rounds;
        private int _index;
        protected uint[] EngineState = new uint[EngineStateSize]; // state
        protected uint[] X = new uint[EngineStateSize]; // internal buffer
        private byte[] _keyStream = new byte[EngineStateSize * 4];

        private uint _cW0, _cW1, _cW2;

        /// <summary>
        /// Creates a 20 round Salsa20 engine.
        /// </summary>
        public Salsa20Engine()
            : this(DefaultRounds) {}

        /// <summary>
        /// Creates a Salsa20 engine with a specific number of rounds.
        /// </summary>
        /// <param name="rounds">the number of rounds (must be an even number).</param>
        public Salsa20Engine(int rounds) : base(StreamCipher.Salsa20)
        {
            if (rounds <= 0 || (rounds & 1) != 0) {
                throw new ArgumentException("'rounds' must be a positive, even number");
            }

            this.Rounds = rounds;
        }

        /// <summary>
        /// Creates a Salsa20 derivative engine with a specific number of rounds.
        /// </summary>
        /// <param name="rounds">the number of rounds (must be an even number).</param>
        protected Salsa20Engine(StreamCipher cipherIdentity, int rounds)
            : base(cipherIdentity)
        {
            if (rounds <= 0 || (rounds & 1) != 0) {
                throw new ArgumentException("'rounds' must be a positive, even number");
            }

            this.Rounds = rounds;
        }

        /// <inheritdoc />
        protected override void InitState()
        {
            SetKey(Key, Nonce);
            Reset();
            IsInitialised = true;
        }

        /// <inheritdoc />
        public override string AlgorithmName
        {
            get
            {
                if (Rounds != DefaultRounds) {
                    return CipherName + "/" + Rounds;
                } else {
                    return CipherName;
                }
            }
        }

        /// <inheritdoc />
        public override int StateSize
        {
            get { return 64; }
        }

        /// <inheritdoc />
        public override byte ReturnByte(
            byte input)
        {
            if (LimitExceeded()) {
                throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
            }

            if (_index == 0) {
                GenerateKeyStream(_keyStream, 0);
                AdvanceCounter();
            }

            byte output = (byte) (_keyStream[_index] ^ input);
            _index = (_index + 1) & 63;

            return output;
        }

        protected void AdvanceCounter()
        {
            if (++EngineState[8] == 0) {
                ++EngineState[9];
            }
        }

        /// <inheritdoc />
        internal override void ProcessBytesInternal(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            if (LimitExceeded((uint)length)) {
                throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
            }

            // Any left over from last time?
            if (_index > 0) {
                var blen = StrideSize - _index;
                if (blen > length) {
                    blen = length;
                }
                input.XorInternal(inOff, _keyStream, _index, output, outOff, blen);
                _index += blen;
                inOff += blen;
                outOff += blen;
                length -= blen;
            }

            int remainder;
            var blocks = Math.DivRem(length, StrideSize, out remainder);

#if INCLUDE_UNSAFE
            unsafe {
                fixed (byte* inPtr = input) {
                    fixed (byte* outPtr = output) {
                        for (var i = 0; i < blocks; i++) {
                            ProcessStride(inPtr + inOff + (StrideSize * i),
                                outPtr + outOff + (StrideSize * i));
                            AdvanceCounter();
                        }
                    }
                }
            }
            inOff += StrideSize * blocks;
            outOff += StrideSize * blocks;
#else
            for (var i = 0; i < blocks; i++) {
                GenerateKeyStream(_keyStream, 0);
                AdvanceCounter();
                input.Xor(inOff, _keyStream, 0, output, outOff, StrideSize);
                inOff += StrideSize;
                outOff += StrideSize;
            }
#endif

            if (remainder > 0) {
                GenerateKeyStream(_keyStream, 0);
                AdvanceCounter();
                input.XorInternal(inOff, _keyStream, 0, output, outOff, remainder);
            }
            _index = remainder;
        }

        /// <inheritdoc />
        public void GetKeystream(byte[] buffer, int offset, int length)
        {
            if (_index > 0) {
                var blen = StrideSize - _index;
                if (blen > length) {
                    blen = length;
                }
                _keyStream.CopyBytes(_index, buffer, offset, blen);
                _index += blen;
                offset += blen;
                length -= blen;
            }
            while (length > 0) {
                if (length >= StrideSize) {
                    GenerateKeyStream(buffer, offset);
                    AdvanceCounter();
                    offset += StrideSize;
                    length -= StrideSize;
                } else {
                    GenerateKeyStream(_keyStream, 0);
                    AdvanceCounter();
                    _keyStream.CopyBytes(0, buffer, offset, length);
                    _index = length;
                    length = 0;
                }
            }
        }

        /// <inheritdoc />
        public override void Reset()
        {
            _index = 0;
            ResetLimitCounter();
            ResetCounter();
        }

        protected void ResetCounter()
        {
            EngineState[8] = EngineState[9] = 0;
        }

        protected virtual void SetKey(byte[] keyBytes, byte[] ivBytes)
        {
            int offset = 0;
            byte[] constants;

            // Key
            EngineState[1] = Pack.LE_To_UInt32(keyBytes, 0);
            EngineState[2] = Pack.LE_To_UInt32(keyBytes, 4);
            EngineState[3] = Pack.LE_To_UInt32(keyBytes, 8);
            EngineState[4] = Pack.LE_To_UInt32(keyBytes, 12);

            if (keyBytes.Length == 32) {
                constants = Sigma;
                offset = 16;
            } else {
                constants = Tau;
            }

            EngineState[11] = Pack.LE_To_UInt32(keyBytes, offset);
            EngineState[12] = Pack.LE_To_UInt32(keyBytes, offset + 4);
            EngineState[13] = Pack.LE_To_UInt32(keyBytes, offset + 8);
            EngineState[14] = Pack.LE_To_UInt32(keyBytes, offset + 12);

            // Constants
            EngineState[0] = Pack.LE_To_UInt32(constants, 0);
            EngineState[5] = Pack.LE_To_UInt32(constants, 4);
            EngineState[10] = Pack.LE_To_UInt32(constants, 8);
            EngineState[15] = Pack.LE_To_UInt32(constants, 12);

            // IV
            EngineState[6] = Pack.LE_To_UInt32(ivBytes, 0);
            EngineState[7] = Pack.LE_To_UInt32(ivBytes, 4);
            ResetCounter();
        }

        protected virtual void GenerateKeyStream(byte[] output, int offset)
        {
            SalsaCoreNoChecks(Rounds, EngineState, X);
            Pack.UInt32_To_LE(X, output, offset);
        }

#if INCLUDE_UNSAFE
        protected unsafe void ProcessStride(byte* input, byte* output)
        {
            SalsaCoreNoChecks(Rounds, EngineState, X);
            int ops = X.Length;

            var inPtr = (uint*)input;
            var outPtr = (uint*)output;
            for (var i = 0; i < ops; i++) {
                outPtr[i] = inPtr[i] ^ X[i];
            }
        }
#endif

        /// <summary>
        /// Salsa function.
        /// </summary>
        /// <param name="rounds">The number of Salsa rounds to execute</param>
        /// <param name="input">The input words.</param>
        /// <param name="x">The Salsa state to modify.</param>
        internal static void SalsaCore(int rounds, uint[] input, uint[] x)
        {
            if (input.Length != 16) {
                throw new ArgumentException("Incorrect length (not 16).", "input");
            } else if (x.Length != 16) {
                throw new ArgumentException("Incorrect length (not 16).", "x");
            }
            if (rounds % 2 != 0) {
                throw new ArgumentException("Number of rounds must be even");
            }

            SalsaCoreNoChecks(rounds, input, x);
        }

        internal static void SalsaCoreNoChecks(int rounds, uint[] input, uint[] x)
        {
            uint x00 = input[0];
            uint x01 = input[1];
            uint x02 = input[2];
            uint x03 = input[3];
            uint x04 = input[4];
            uint x05 = input[5];
            uint x06 = input[6];
            uint x07 = input[7];
            uint x08 = input[8];
            uint x09 = input[9];
            uint x10 = input[10];
            uint x11 = input[11];
            uint x12 = input[12];
            uint x13 = input[13];
            uint x14 = input[14];
            uint x15 = input[15];

            for (int i = rounds; i > 0; i -= 2) {
                x04 ^= R((x00 + x12), 7);
                x08 ^= R((x04 + x00), 9);
                x12 ^= R((x08 + x04), 13);
                x00 ^= R((x12 + x08), 18);
                x09 ^= R((x05 + x01), 7);
                x13 ^= R((x09 + x05), 9);
                x01 ^= R((x13 + x09), 13);
                x05 ^= R((x01 + x13), 18);
                x14 ^= R((x10 + x06), 7);
                x02 ^= R((x14 + x10), 9);
                x06 ^= R((x02 + x14), 13);
                x10 ^= R((x06 + x02), 18);
                x03 ^= R((x15 + x11), 7);
                x07 ^= R((x03 + x15), 9);
                x11 ^= R((x07 + x03), 13);
                x15 ^= R((x11 + x07), 18);

                x01 ^= R((x00 + x03), 7);
                x02 ^= R((x01 + x00), 9);
                x03 ^= R((x02 + x01), 13);
                x00 ^= R((x03 + x02), 18);
                x06 ^= R((x05 + x04), 7);
                x07 ^= R((x06 + x05), 9);
                x04 ^= R((x07 + x06), 13);
                x05 ^= R((x04 + x07), 18);
                x11 ^= R((x10 + x09), 7);
                x08 ^= R((x11 + x10), 9);
                x09 ^= R((x08 + x11), 13);
                x10 ^= R((x09 + x08), 18);
                x12 ^= R((x15 + x14), 7);
                x13 ^= R((x12 + x15), 9);
                x14 ^= R((x13 + x12), 13);
                x15 ^= R((x14 + x13), 18);
            }

            x[0] = x00 + input[0];
            x[1] = x01 + input[1];
            x[2] = x02 + input[2];
            x[3] = x03 + input[3];
            x[4] = x04 + input[4];
            x[5] = x05 + input[5];
            x[6] = x06 + input[6];
            x[7] = x07 + input[7];
            x[8] = x08 + input[8];
            x[9] = x09 + input[9];
            x[10] = x10 + input[10];
            x[11] = x11 + input[11];
            x[12] = x12 + input[12];
            x[13] = x13 + input[13];
            x[14] = x14 + input[14];
            x[15] = x15 + input[15];
        }

        protected internal static void HSalsa20(byte[] output, int outputOffset, byte[] key, byte[] nonce)
        {
            var block = XSalsa20Engine.PrepareHSalsaBlock(key, nonce);
            Salsa20Engine.HSalsa(20, block, 0, block, 0);

            Pack.UInt32_To_LE(block[0], output, outputOffset + 0);
            Pack.UInt32_To_LE(block[5], output, outputOffset + 4);
            Pack.UInt32_To_LE(block[10], output, outputOffset + 8);
            Pack.UInt32_To_LE(block[15], output, outputOffset + 12);
            Pack.UInt32_To_LE(block[6], output, outputOffset + 16);
            Pack.UInt32_To_LE(block[7], output, outputOffset + 20);
            Pack.UInt32_To_LE(block[8], output, outputOffset + 24);
            Pack.UInt32_To_LE(block[9], output, outputOffset + 28);
        }

        protected internal static void HSalsa(int rounds, uint[] input, int inOff, uint[] x, int xOff)
        {
            if (rounds.IsBetween(2, 20) == false || (rounds & 1) == 1) {
                throw new ArgumentException("Must be even and in the range 2 to 20.", "rounds");
            }

            uint x00 = input[inOff + 0];
            uint x01 = input[inOff + 1];
            uint x02 = input[inOff + 2];
            uint x03 = input[inOff + 3];
            uint x04 = input[inOff + 4];
            uint x05 = input[inOff + 5];
            uint x06 = input[inOff + 6];
            uint x07 = input[inOff + 7];
            uint x08 = input[inOff + 8];
            uint x09 = input[inOff + 9];
            uint x10 = input[inOff + 10];
            uint x11 = input[inOff + 11];
            uint x12 = input[inOff + 12];
            uint x13 = input[inOff + 13];
            uint x14 = input[inOff + 14];
            uint x15 = input[inOff + 15];

            for (int i = rounds; i > 0; i -= 2) {
                x04 ^= R((x00 + x12), 7);
                x08 ^= R((x04 + x00), 9);
                x12 ^= R((x08 + x04), 13);
                x00 ^= R((x12 + x08), 18);
                x09 ^= R((x05 + x01), 7);
                x13 ^= R((x09 + x05), 9);
                x01 ^= R((x13 + x09), 13);
                x05 ^= R((x01 + x13), 18);
                x14 ^= R((x10 + x06), 7);
                x02 ^= R((x14 + x10), 9);
                x06 ^= R((x02 + x14), 13);
                x10 ^= R((x06 + x02), 18);
                x03 ^= R((x15 + x11), 7);
                x07 ^= R((x03 + x15), 9);
                x11 ^= R((x07 + x03), 13);
                x15 ^= R((x11 + x07), 18);

                x01 ^= R((x00 + x03), 7);
                x02 ^= R((x01 + x00), 9);
                x03 ^= R((x02 + x01), 13);
                x00 ^= R((x03 + x02), 18);
                x06 ^= R((x05 + x04), 7);
                x07 ^= R((x06 + x05), 9);
                x04 ^= R((x07 + x06), 13);
                x05 ^= R((x04 + x07), 18);
                x11 ^= R((x10 + x09), 7);
                x08 ^= R((x11 + x10), 9);
                x09 ^= R((x08 + x11), 13);
                x10 ^= R((x09 + x08), 18);
                x12 ^= R((x15 + x14), 7);
                x13 ^= R((x12 + x15), 9);
                x14 ^= R((x13 + x12), 13);
                x15 ^= R((x14 + x13), 18);
            }

            x[xOff + 0] = x00;
            x[xOff + 1] = x01;
            x[xOff + 2] = x02;
            x[xOff + 3] = x03;
            x[xOff + 4] = x04;
            x[xOff + 5] = x05;
            x[xOff + 6] = x06;
            x[xOff + 7] = x07;
            x[xOff + 8] = x08;
            x[xOff + 9] = x09;
            x[xOff + 10] = x10;
            x[xOff + 11] = x11;
            x[xOff + 12] = x12;
            x[xOff + 13] = x13;
            x[xOff + 14] = x14;
            x[xOff + 15] = x15;
        }

        /*		*
		 * Rotate left
		 *
		 * @param   x   value to rotate
		 * @param   y   amount to rotate x
		 *
		 * @return  rotated x
		 */

        internal static uint R(uint x, int y)
        {
            return (x << y) | (x >> (32 - y));
        }

        private void ResetLimitCounter()
        {
            _cW0 = 0;
            _cW1 = 0;
            _cW2 = 0;
        }

        private bool LimitExceeded()
        {
            if (++_cW0 == 0) {
                if (++_cW1 == 0) {
                    return (++_cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
                }
            }

            return false;
        }

        private bool LimitExceeded(
            uint len)
        {
            uint old = _cW0;
            _cW0 += len;
            if (_cW0 < old) {
                if (++_cW1 == 0) {
                    return (++_cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
                }
            }

            return false;
        }
    }
}
