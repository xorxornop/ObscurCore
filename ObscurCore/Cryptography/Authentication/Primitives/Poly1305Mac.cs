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

// Ported and refactored/adapted from floodyberry's Poly1305Donna implementation in C

using System;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	public class Poly1305Mac : IMac
	{
		private readonly byte[] _blockBuffer = new byte[16];
		private int _blockBufferOffset;

		private Array8 _key;
		private UInt32 t0, t1, t2, t3;
		private UInt32 h0, h1, h2, h3, h4;
		private UInt32 r0, r1, r2, r3, r4;
		private UInt32 s1, s2, s3, s4;
		private UInt32 b, nb;
		private UInt64[] t;
		private UInt64 c;


		public Poly1305Mac ()
		{
		}

		#region IMac implementation

		public void Init (ICipherParameters parameters)
		{
			byte[] key = new byte[32];
			var keyParameter = parameters as KeyParameter;
			if (keyParameter != null) {
				var keyRaw = keyParameter.GetKey();
				Buffer.BlockCopy (keyRaw, 0, key, 0, key.Length);
			}

			if(key != null) {
				if(key.Length > 32) throw new ArgumentOutOfRangeException("parameters", "Key is longer than 32 bytes.");

				_key = new Array8 {
					x0 = ByteIntegerConverter.LoadLittleEndian32(key, 0),
					x1 = ByteIntegerConverter.LoadLittleEndian32(key, 4),
					x2 = ByteIntegerConverter.LoadLittleEndian32(key, 8),
					x3 = ByteIntegerConverter.LoadLittleEndian32(key, 12),
					x4 = ByteIntegerConverter.LoadLittleEndian32(key, 16),
					x5 = ByteIntegerConverter.LoadLittleEndian32(key, 20),
					x6 = ByteIntegerConverter.LoadLittleEndian32(key, 24),
					x7 = ByteIntegerConverter.LoadLittleEndian32(key, 28)
				};

			} else {
				throw new ArgumentException ("No key provided.");
			}

			Reset ();
		}

		public void Update (byte input)
		{
			_blockBuffer [_blockBufferOffset] = input;
			_blockBufferOffset++;

			if(_blockBufferOffset > 15) {
				DoBlock (_blockBuffer, 0);
				_blockBufferOffset = 0;
			}
		}

		public void BlockUpdate (byte[] input, int inOff, int len)
		{
			// Any left over from last time?
			if(_blockBufferOffset > 0) {
				int requiredChunkSize = 16 - _blockBufferOffset;
				Buffer.BlockCopy (input, inOff, _blockBuffer, _blockBufferOffset, requiredChunkSize);
				DoBlock (_blockBuffer, 0);
				_blockBufferOffset = 0;
			}
			// Process all the whole blocks
			while (len >= 16) {
				DoBlock (input, inOff);
				inOff += 16;
				len -= 16;
			}
			// Any left?
			if(len > 0) {
				Buffer.BlockCopy (input, inOff, _blockBuffer, _blockBufferOffset, len);
				_blockBufferOffset += len;
			}
		}

		/// <summary>
		/// Process a whole 16 byte block.
		/// </summary>
		/// <param name="m">Input message.</param>
		/// <param name="mStart">Input message offset.</param>
		private void DoBlock(byte[] m, int mStart) {
			t0 = ByteIntegerConverter.LoadLittleEndian32(m, 0);
			t1 = ByteIntegerConverter.LoadLittleEndian32(m, 4);
			t2 = ByteIntegerConverter.LoadLittleEndian32(m, 8);
			t3 = ByteIntegerConverter.LoadLittleEndian32(m, 12);

			h0 += t0 & 0x3ffffff;
			h1 += (uint)(((((UInt64)t1 << 32) | t0) >> 26) & 0x3ffffff);
			h2 += (uint)(((((UInt64)t2 << 32) | t1) >> 20) & 0x3ffffff);
			h3 += (uint)(((((UInt64)t3 << 32) | t2) >> 14) & 0x3ffffff);
			h4 += (t3 >> 8) | (1 << 24);

			Mul ();
		}

		private void Mul() {
			t[0] = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
			t[1] = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
			t[2] = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
			t[3] = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
			t[4] = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

			h0 = (UInt32)t[0] & 0x3ffffff; c = (t[0] >> 26);
			t[1] += c; h1 = (UInt32)t[1] & 0x3ffffff; b = (UInt32)(t[1] >> 26);
			t[2] += b; h2 = (UInt32)t[2] & 0x3ffffff; b = (UInt32)(t[2] >> 26);
			t[3] += b; h3 = (UInt32)t[3] & 0x3ffffff; b = (UInt32)(t[3] >> 26);
			t[4] += b; h4 = (UInt32)t[4] & 0x3ffffff; b = (UInt32)(t[4] >> 26);
			h0 += b * 5;
		}

		public int DoFinal (byte[] output, int outOff)
		{
			if(_blockBufferOffset > 0) {
				byte[] mp = new byte[16];
				int j;
				for (j = 0; j < _blockBufferOffset; j++)
					mp[j] = _blockBuffer[j];
				mp[j++] = 1;
				for (; j < 16; j++)
					mp[j] = 0;
				_blockBufferOffset = 0;

				t0 = ByteIntegerConverter.LoadLittleEndian32(mp, 0);
				t1 = ByteIntegerConverter.LoadLittleEndian32(mp, 4);
				t2 = ByteIntegerConverter.LoadLittleEndian32(mp, 8);
				t3 = ByteIntegerConverter.LoadLittleEndian32(mp, 12);

				h0 += t0 & 0x3ffffff;
				h1 += (uint)(((((UInt64)t1 << 32) | t0) >> 26) & 0x3ffffff);
				h2 += (uint)(((((UInt64)t2 << 32) | t1) >> 20) & 0x3ffffff);
				h3 += (uint)(((((UInt64)t3 << 32) | t2) >> 14) & 0x3ffffff);
				h4 += t3 >> 8;

				Mul ();
			}

			UInt64 f0, f1, f2, f3;
			UInt32 g0, g1, g2, g3, g4;

			b = h0 >> 26; h0 = h0 & 0x3ffffff;
			h1 += b; b = h1 >> 26; h1 = h1 & 0x3ffffff;
			h2 += b; b = h2 >> 26; h2 = h2 & 0x3ffffff;
			h3 += b; b = h3 >> 26; h3 = h3 & 0x3ffffff;
			h4 += b; b = h4 >> 26; h4 = h4 & 0x3ffffff;
			h0 += b * 5;

			g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
			g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
			g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
			g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
			g4 = h4 + b - (1 << 26);

			b = (g4 >> 31) - 1;
			nb = ~b;
			h0 = (h0 & nb) | (g0 & b);
			h1 = (h1 & nb) | (g1 & b);
			h2 = (h2 & nb) | (g2 & b);
			h3 = (h3 & nb) | (g3 & b);
			h4 = (h4 & nb) | (g4 & b);

			f0 = ((h0) | (h1 << 26)) + (UInt64)_key.x4;
			f1 = ((h1 >> 6) | (h2 << 20)) + (UInt64)_key.x5;
			f2 = ((h2 >> 12) | (h3 << 14)) + (UInt64)_key.x6;
			f3 = ((h3 >> 18) | (h4 << 8)) + (UInt64)_key.x7;

			ByteIntegerConverter.StoreLittleEndian32(output, outOff + 0, (uint)f0); f1 += (f0 >> 32);
			ByteIntegerConverter.StoreLittleEndian32(output, outOff + 4, (uint)f1); f2 += (f1 >> 32);
			ByteIntegerConverter.StoreLittleEndian32(output, outOff + 8, (uint)f2); f3 += (f2 >> 32);
			ByteIntegerConverter.StoreLittleEndian32(output, outOff + 12, (uint)f3);

			return 16;
		}

		public void Reset ()
		{
			/* clamp key */
			t0 = _key.x0;
			t1 = _key.x1;
			t2 = _key.x2;
			t3 = _key.x3;

			/*			 precompute multipliers */
			r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
			r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
			r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
			r3 = t2 & 0x3f03fff; t3 >>= 8;
			r4 = t3 & 0x00fffff;

			s1 = r1 * 5;
			s2 = r2 * 5;
			s3 = r3 * 5;
			s4 = r4 * 5;

			/*			 init state */
			h0 = 0;
			h1 = 0;
			h2 = 0;
			h3 = 0;
			h4 = 0;

			b = 0;
			nb = 0;
			t = new UInt64[5];
			c = 0;
		}

		public string AlgorithmName {
			get {
				return "Poly1305";
			}
		}

		public int MacSize {
			get {
				return 16;
			}
		}

		#endregion

		internal struct Array8
		{
			public UInt32 x0;
			public UInt32 x1;
			public UInt32 x2;
			public UInt32 x3;
			public UInt32 x4;
			public UInt32 x5;
			public UInt32 x6;
			public UInt32 x7;
		}

		private static class ByteIntegerConverter
		{
			public static UInt32 LoadLittleEndian32(byte[] buf, int offset)
			{
				return
					(UInt32)(buf[offset + 0])
					| (((UInt32)(buf[offset + 1])) << 8)
					| (((UInt32)(buf[offset + 2])) << 16)
					| (((UInt32)(buf[offset + 3])) << 24);
			}

			public static void StoreLittleEndian32(byte[] buf, int offset, UInt32 value)
			{
				buf[offset + 0] = (byte)value;
				buf[offset + 1] = (byte)(value >> 8);
				buf[offset + 2] = (byte)(value >> 16);
				buf[offset + 3] = (byte)(value >> 24);
			}
		}
	}
}

