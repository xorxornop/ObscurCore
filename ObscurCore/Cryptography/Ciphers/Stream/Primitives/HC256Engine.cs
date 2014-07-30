using System;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	/**
	* HC-256 is a software-efficient stream cipher created by Hongjun Wu. It 
	* generates keystream from a 256-bit secret key and a 256-bit initialization 
	* vector.
	* <p>
	* http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc256_p3.pdf
	* </p><p>
	* Its brother, HC-128, is a third phase candidate in the eStream contest.
	* The algorithm is patent-free. No attacks are known as of today (April 2007). 
	* See
	* 
	* http://www.ecrypt.eu.org/stream/hcp3.html
	* </p>
	*/
	public class Hc256Engine
		: StreamCipherEngine
	{
		private uint[] _p = new uint[1024];
		private uint[] _q = new uint[1024];
		private uint _cnt;

        public Hc256Engine()
            : base(StreamCipher.Hc256)
	    {
	    }

		private uint Step()
		{
			uint j = _cnt & 0x3FF;
			uint ret;
			if (_cnt < 1024)
			{
				uint x = _p[(j - 3 & 0x3FF)];
				uint y = _p[(j - 1023 & 0x3FF)];
				_p[j] += _p[(j - 10 & 0x3FF)]
                    + (x.RotateRight(10) ^ y.RotateRight(23))
					+ _q[((x ^ y) & 0x3FF)];

				x = _p[(j - 12 & 0x3FF)];
				ret = (_q[x & 0xFF] + _q[((x >> 8) & 0xFF) + 256]
					+ _q[((x >> 16) & 0xFF) + 512] + _q[((x >> 24) & 0xFF) + 768])
					^ _p[j];
			}
			else
			{
				uint x = _q[(j - 3 & 0x3FF)];
				uint y = _q[(j - 1023 & 0x3FF)];
				_q[j] += _q[(j - 10 & 0x3FF)]
                    + (x.RotateRight(10) ^ y.RotateRight(23))
					+ _p[((x ^ y) & 0x3FF)];

				x = _q[(j - 12 & 0x3FF)];
				ret = (_p[x & 0xFF] + _p[((x >> 8) & 0xFF) + 256]
					+ _p[((x >> 16) & 0xFF) + 512] + _p[((x >> 24) & 0xFF) + 768])
					^ _q[j];
			}
			_cnt = _cnt + 1 & 0x7FF;
			return ret;
		}

		private void Init()
		{
			if (Key.Length != 32) {
				byte[] k = new byte[32];

                Array.Copy(Key, 0, k, 0, Key.Length);
                Array.Copy(Key, 0, k, 16, Key.Length);

                Key = k;
			}

			if (Nonce.Length < 32) {
				byte[] newIV = new byte[32];

                Array.Copy(Nonce, 0, newIV, 0, Nonce.Length);
                Array.Copy(Nonce, 0, newIV, Nonce.Length, newIV.Length - Nonce.Length);

                Nonce = newIV;
			}

			_cnt = 0;

			uint[] w = new uint[2560];

			for (int i = 0; i < 32; i++)
			{
				w[i >> 2] |= ((uint)Key[i] << (8 * (i & 0x3)));
			}

			for (int i = 0; i < 32; i++)
			{
                w[(i >> 2) + 8] |= ((uint)Nonce[i] << (8 * (i & 0x3)));
			}

			for (uint i = 16; i < 2560; i++)
			{
				uint x = w[i - 2];
				uint y = w[i - 15];
                w[i] = (x.RotateRight(17) ^ x.RotateRight(19) ^ (x >> 10))
                    + w[i - 7]
                    + (y.RotateRight(7) ^ y.RotateRight(18) ^ (y >> 3))
                    + w[i - 16] + i;
			}

			Buffer.BlockCopy(w, 512 * sizeof(uint), _p, 0, 1024 * sizeof(uint));
			Buffer.BlockCopy(w, 1536 * sizeof(uint), _q, 0, 1024 * sizeof(uint));

			for (int i = 0; i < 4096; i++)
			{
				Step();
			}

			_cnt = 0;
		}

        /// <inheritdoc/>
		public override string AlgorithmName
		{
			get { return "HC-256"; }
		}

        /// <inheritdoc/>
		public override int StateSize
		{
			get { return 32; }
		}

	    protected override void InitState()
	    {
            Init();
            IsInitialised = true;
	    }

	    private byte[] buf = new byte[4];
		private int idx;

		private byte GetByte()
		{
			if (idx == 0)
			{
				Pack.UInt32_To_LE(Step(), buf);
			}
			byte ret = buf[idx];
			idx = (idx + 1) & 3;
			return ret;
		}

        /// <inheritdoc/>
		internal override void ProcessBytesInternal(
			byte[]	input,
			int		inOff,
			int		len,
			byte[]	output,
			int		outOff)
		{
			// Process leftover keystream
			for (; idx != 0; idx = (idx + 1) & 3) {
				output[outOff++] = (byte)(input[inOff++] ^ buf[idx]);
				len--;
			}

			int remainder;
			int blocks = Math.DivRem (len, 4, out remainder);

			#if INCLUDE_UNSAFE
            unsafe {
                fixed (byte* inPtr = input) {
                    fixed (byte* outPtr = output) {
                        uint* inUintPtr = (uint*)(inPtr + inOff);
                        uint* outUintPtr = (uint*)(outPtr + outOff);
                        for (int i = 0; i < blocks; i++) {
                            uint j = _cnt & 0x3FF;
                            uint ret;
                            if (_cnt < 1024) {
                                uint x = _p[(j - 3 & 0x3FF)];
                                uint y = _p[(j - 1023 & 0x3FF)];
                                _p[j] += _p[(j - 10 & 0x3FF)]
                                    + (x.RotateRight(10) ^ y.RotateRight(23))
                                    + _q[((x ^ y) & 0x3FF)];

                                x = _p[(j - 12 & 0x3FF)];
                                ret = (_q[x & 0xFF] + _q[((x >> 8) & 0xFF) + 256]
                                    + _q[((x >> 16) & 0xFF) + 512] + _q[((x >> 24) & 0xFF) + 768])
                                    ^ _p[j];
                            } else {
                                uint x = _q[(j - 3 & 0x3FF)];
                                uint y = _q[(j - 1023 & 0x3FF)];
                                _q[j] += _q[(j - 10 & 0x3FF)]
                                    + (x.RotateRight(10) ^ y.RotateRight(23))
                                    + _p[((x ^ y) & 0x3FF)];

                                x = _q[(j - 12 & 0x3FF)];
                                ret = (_p[x & 0xFF] + _p[((x >> 8) & 0xFF) + 256]
                                    + _p[((x >> 16) & 0xFF) + 512] + _p[((x >> 24) & 0xFF) + 768])
                                    ^ _q[j];
                            }
                            _cnt = _cnt + 1 & 0x7FF;
                            outUintPtr[i] = inUintPtr[i] ^ ret;
                        }
                    }
                }
            }
            inOff += 4 * blocks;
            outOff += 4 * blocks;
			#else
			for (int i = 0; i < blocks; i++) {
				Pack.UInt32_To_LE(Step(), buf);
				output[outOff + 0] = (byte)(input[inOff + 0] ^ buf[0]);
				output[outOff + 1] = (byte)(input[inOff + 1] ^ buf[1]);
				output[outOff + 2] = (byte)(input[inOff + 2] ^ buf[2]);
				output[outOff + 3] = (byte)(input[inOff + 3] ^ buf[3]);
				inOff += 4;
				outOff += 4;
			}
			#endif

			// Process remainder input (insufficient width for a full step)
			for (int i = 0; i < remainder; i++) {
				if (idx == 0) {
					Pack.UInt32_To_LE(Step(), buf);
				}
				output[outOff++] = (byte)(input[inOff++] ^ buf[idx]);
				idx = (idx + 1) & 3;
			}
		}

        /// <inheritdoc/>
		public override void Reset()
		{
			idx = 0;
			Init();
		}

        /// <inheritdoc/>
		public override byte ReturnByte(byte input)
		{
			return (byte)(input ^ GetByte());
		}
	}
	
}
