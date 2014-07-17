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

	public class Hc128Engine : IStreamCipher
	{
		private uint[] p = new uint[512];
		private uint[] q = new uint[512];
		private uint cnt = 0;

		private static uint F1(uint x)
		{
			return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
		}

		private static uint F2(uint x)
		{
			return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
		}

		private uint G1(uint x, uint y, uint z)
		{
			return (RotateRight(x, 10) ^ RotateRight(z, 23)) + RotateRight(y, 8);
		}

		private uint G2(uint x, uint y, uint z)
		{
			return (RotateLeft(x, 10) ^ RotateLeft(z, 23)) + RotateLeft(y, 8);
		}

		private static uint RotateLeft(uint	x, int bits)
		{
			return (x << bits) | (x >> -bits);
		}

		private static uint RotateRight(uint x, int bits)
		{
			return (x >> bits) | (x << -bits);
		}

		private uint H1(uint x)
		{
			return q[x & 0xFF] + q[((x >> 16) & 0xFF) + 256];
		}

		private uint H2(uint x)
		{
			return p[x & 0xFF] + p[((x >> 16) & 0xFF) + 256];
		}

		private static uint Mod1024(uint x)
		{
			return x & 0x3FF;
		}

		private static uint Mod512(uint x)
		{
			return x & 0x1FF;
		}

		private static uint Dim(uint x, uint y)
		{
			return Mod512(x - y);
		}

		private uint Step () {
			//uint j = Mod512(cnt);
			uint j = cnt & 0x1FF;
			uint ret;

			// Precompute resources
			uint dimJ3 = (j - 3) & 0x1FF;
			uint dimJ10 = (j - 10) & 0x1FF;
			uint dimJ511 = (j - 511) & 0x1FF;
			uint dimJ12 = (j - 12) & 0x1FF;

			if (cnt < 512) {
				//p[j] += G1(p[Dim(j, 3)], p[Dim(j, 10)], p[Dim(j, 511)]);
				p[j] += (RotateRight(p[dimJ3], 10) ^ RotateRight(p[dimJ511], 23)) + RotateRight(p[dimJ10], 8);
				//ret = H1(p[Dim(j, 12)]) ^ p[j];
				ret = (q[p[dimJ12] & 0xFF] + q[((p[dimJ12] >> 16) & 0xFF) + 256]) ^ p[j];
			} else {
				//q[j] += G2(q[Dim(j, 3)], q[Dim(j, 10)], q[Dim(j, 511)]);
				q[j] += (RotateLeft(q[dimJ3], 10) ^ RotateLeft(q[dimJ511], 23)) + RotateLeft(q[dimJ10], 8);
				//ret = H2(q[Dim(j, 12)]) ^ q[j];
				ret = (p[q[dimJ12] & 0xFF] + p[((q[dimJ12] >> 16) & 0xFF) + 256]) ^ q[j];
			}
			//cnt = Mod1024(cnt + 1);
			cnt = (cnt + 1) & 0x3FF;
			return ret;
		}

		private byte[] key, iv;
		private bool initialised;

		private void Init() {
			cnt = 0;

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
				w[i] = F2(w[i - 2]) + w[i - 7] + F1(w[i - 15]) + w[i - 16] + i;
			}

			Buffer.BlockCopy (w, 256 * sizeof(uint), p, 0, 512 * sizeof(uint));
			Buffer.BlockCopy (w, 768 * sizeof(uint), q, 0, 512 * sizeof(uint));

			for (int i = 0; i < 512; i++) {
				p[i] = Step();
			}
			for (int i = 0; i < 512; i++) {
				q[i] = Step();
			}

			cnt = 0;
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
			if(iv == null) {
				throw new ArgumentNullException("iv", "HC-256 initialisation requires an IV.");
			} else if (key.Length != 16) {
				throw new ArgumentException ("HC-256 requires an exactly 16 byte IV.", "iv");
			}
			this.iv = iv;


			Init ();
			initialised = true;
		}

		private byte[] buf = new byte[4];
		private int idx = 0;

		private byte GetByte()
		{
			if (idx == 0)
			{
				Pack.UInt32_To_LE(Step(), buf);				
			}
			byte ret = buf[idx];
			idx = idx + 1 & 0x3;
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
            int blocks = Math.DivRem(len, sizeof(uint), out remainder);

			#if INCLUDE_UNSAFE
            unsafe {
                fixed (byte* inPtr = input) {
                    fixed (byte* outPtr = output) {
                        uint* inUintPtr = (uint*)(inPtr + inOff);
                        uint* outUintPtr = (uint*)(outPtr + outOff);
                        for (int i = 0; i < blocks; i++) {
                            outUintPtr[i] = inUintPtr[i] ^ Step();
                        }
                    }
                }
            }
            inOff += sizeof(uint) * blocks;
            outOff += sizeof(uint) * blocks;
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

		public void Reset()
		{
			idx = 0;
			Init();
		}

		public byte ReturnByte(byte input)
		{
			return (byte)(input ^ GetByte());
		}
	}
}
