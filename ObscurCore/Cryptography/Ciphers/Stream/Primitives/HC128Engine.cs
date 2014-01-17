//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using System;
using ObscurCore.Cryptography.Support;

// Optimised by Matthew Ducker from original BC source. Removed method calls.

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	/**
	* HC-128 is a software-efficient stream cipher created by Hongjun Wu. It
	* generates keystream from a 128-bit secret key and a 128-bit initialization
	* vector.
	* <p>
	* http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
	* </p><p>
	* It is a third phase candidate in the eStream contest, and is patent-free.
	* No attacks are known as of today (April 2007). See
	*
	* http://www.ecrypt.eu.org/stream/hcp3.html
	* </p>
	*/
	public class Hc128Engine
		: IStreamCipher
	{
		private readonly uint[] _p = new uint[512];
		private readonly uint[] _q = new uint[512];
		private uint _cnt;

        //private static uint F1(uint x)
        //{
        //    return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
        //}

        //private static uint F2(uint x)
        //{
        //    return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
        //}

        //private uint G1(uint x, uint y, uint z)
        //{
        //    return (RotateRight(x, 10) ^ RotateRight(z, 23)) + RotateRight(y, 8);
        //}

        //private uint G2(uint x, uint y, uint z)
        //{
        //    return (RotateLeft(x, 10) ^ RotateLeft(z, 23)) + RotateLeft(y, 8);
        //}

		private static uint RotateLeft(uint	x, int bits) {
			return (x << bits) | (x >> -bits);
		}

		private static uint RotateRight(uint x, int bits) {
			return (x >> bits) | (x << -bits);
		}

        //private uint H1(uint x)
        //{
        //    return q[x & 0xFF] + q[((x >> 16) & 0xFF) + 256];
        //}

        //private uint H2(uint x)
        //{
        //    return p[x & 0xFF] + p[((x >> 16) & 0xFF) + 256];
        //}

        //private static uint Mod1024(uint x)
        //{
        //    return x & 0x3FF;
        //}

        //private static uint Mod512(uint x)
        //{
        //    return x & 0x1FF;
        //}

        //private static uint Dim(uint x, uint y)
        //{
        //    return Mod512(x - y);
        //}

		private uint Step()
		{
            //Mod512(cnt);
			uint j = _cnt & 0x1FF; 
			uint ret;
			if (_cnt < 512) {
				//p[j] += G1(p[Dim(j, 3)], p[Dim(j, 10)], p[Dim(j, 511)]);
                // ## G1 = RotateRight((j - 3) & 0x1FF, 10) ^ RotateRight((j - 10) & 0x1FF, 23)) + RotateRight((j - 511) & 0x1FF, 8);

                _p[j] += RotateRight((j-3) & 0x1FF, 10) ^ RotateRight((j - 10) & 0x1FF, 23) + RotateRight((j - 511) & 0x1FF, 8);

				//ret = H1(p[Dim(j, 12)]) ^ p[j];
                // ## H1 = q[x & 0xFF] + q[((x >> 16) & 0xFF) + 256];

                uint x = _p[(j - 12) & 0x1FF];
			    ret = _q[x & 0xFF] + _q[((x >> 16) & 0xFF) + 256];

			} else {
				// q[j] += G2(q[Dim(j, 3)], q[Dim(j, 10)], q[Dim(j, 511)]);
                // ## G2 = (RotateLeft(x, 10) ^ RotateLeft(z, 23)) + RotateLeft(y, 8)

                _q[j] += RotateLeft((j - 3) & 0x1FF, 10) ^ RotateLeft((j - 10) & 0x1FF, 23) + RotateLeft((j - 511) & 0x1FF, 8);

				//ret = H2(q[Dim(j, 12)]) ^ q[j];
                // ## H2 = p[x & 0xFF] + p[((x >> 16) & 0xFF) + 256];

                uint x = _p[(j - 12) & 0x1FF];
                ret = _p[x & 0xFF] + _p[((x >> 16) & 0xFF) + 256];
			}
			
            //cnt = Mod1024(cnt + 1);

            _cnt = (_cnt + 1) & 0x3FF;

			return ret;
		}

		private byte[] key, iv;
		private bool initialised;

		private void Init()
		{
			if (key.Length != 16)
				throw new ArgumentException("The key must be 128 bits long");

			_cnt = 0;

			uint[] w = new uint[1280];

			for (int i = 0; i < 16; i++) {
				w[i >> 2] |= ((uint)key[i] << (8 * (i & 0x3)));
			}
			Array.Copy(w, 0, w, 4, 4);

			for (int i = 0; i < iv.Length && i < 16; i++) {
				w[(i >> 2) + 8] |= ((uint)iv[i] << (8 * (i & 0x3)));
			}
			Array.Copy(w, 8, w, 12, 4);

			for (uint i = 16; i < 1280; i++) {
                //w[i] = F2(w[i - 2]) + w[i - 7] + F1(w[i - 15]) + w[i - 16] + i;

                // ## F1 = RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
                // ## F2 = RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);

			    uint x = w[i - 2];
                uint y = w[i - 15];
                w[i] = (RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3)) + w[i - 7]
					+ (RotateRight(y, 17) ^ RotateRight(y, 19) ^ (y >> 10))
					+ w[i - 16] + i;
			}

			Array.Copy(w, 256, _p, 0, 512);
			Array.Copy(w, 768, _q, 0, 512);

			for (int i = 0; i < 512; i++) {
				_p[i] = Step();
			}
			for (int i = 0; i < 512; i++) {
				_q[i] = Step();
			}

			_cnt = 0;
		}

		public string AlgorithmName
		{
			get { return "HC-128"; }
		}

		public int StateSize
		{
			get { return 32; }
		}


		public void Init (bool encrypting, byte[] key, byte[] iv) {
			this.iv = iv ?? new byte[0];
			if(key == null) {
				throw new ArgumentNullException("key", "HC-128 initialisation requires a key.");
			} else if (key.Length != 16) {
				throw new ArgumentException ("HC-128 requires an exactly 16 byte key.");
			}
			this.key = key;
			Init ();
			initialised = true;
		}

		private byte[] buf = new byte[4];
		private int idx;

		private byte GetByte() {
			if (idx == 0) {
				Pack.UInt32_To_LE(Step(), buf);				
			}
			byte ret = buf[idx];
			idx = (idx + 1) & 3;
			return ret;
		}

		public void ProcessBytes(
			byte[]	input,
			int		inOff,
			int		len,
			byte[]	output,
			int		outOff)
		{
			if (!initialised)
				throw new InvalidOperationException(AlgorithmName + " not initialised");
			if ((inOff + len) > input.Length)
				throw new DataLengthException("input buffer too short");
			if ((outOff + len) > output.Length)
				throw new DataLengthException("output buffer too short");

			// Process leftover keystream
			for (; idx != 0; idx = (idx + 1) & 3) {
				output[outOff++] = (byte)(input[inOff++] ^ buf[idx]);
				len--;
			}

			int remainder;
			int blocks = Math.DivRem (len, 4, out remainder);

			#if INCLUDE_UNSAFE
			if(BitConverter.IsLittleEndian) {
				unsafe {
					fixed (byte* inPtr = input) {
						fixed (byte* outPtr = output) {
							uint* inLongPtr = (uint*)(inPtr + inOff);
							uint* outLongPtr = (uint*)(outPtr + outOff);
							for (int i = 0; i < blocks; i++) {
								outLongPtr [0] = inLongPtr [0] ^ Step ();
								inLongPtr++;
								outLongPtr++;
							}
						}
					}
				}
				inOff += 4 * blocks;
				outOff += 4 * blocks;
			} else {
				for (int i = 0; i < blocks; i++) {
					Pack.UInt32_To_LE(Step(), buf);
					output[outOff + 0] = (byte)(input[inOff + 0] ^ buf[0]);
					output[outOff + 1] = (byte)(input[inOff + 1] ^ buf[1]);
					output[outOff + 2] = (byte)(input[inOff + 2] ^ buf[2]);
					output[outOff + 3] = (byte)(input[inOff + 3] ^ buf[3]);
					inOff += 4;
					outOff += 4;
				}
			}
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

		public void Reset() {
			idx = 0;
			Init();
		}

		public byte ReturnByte(byte input) {
			return (byte)(input ^ GetByte());
		}
	}
}
