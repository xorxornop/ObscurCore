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
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Authentication.Primitives
{

	/// <summary>
	/// Poly1305 message authentication code, designed by D. J. Bernstein.
	/// </summary>
	/// <remarks>
	/// Poly1305 computes a 128-bit (16 bytes) authenticator, using a 128 bit nonce and a 256 bit key
	/// consisting of a 128 bit key applied to an underlying cipher, and a 128 bit key (with 106
	/// effective key bits) used in the authenticator.
	/// 
	/// The polynomial calculation in this implementation is adapted from the public domain <a
	/// href="https://github.com/floodyberry/poly1305-donna">poly1305-donna-unrolled</a> C implementation
	/// by Andrew M (@floodyberry).
	/// </remarks>
	/// <seealso cref="Org.BouncyCastle.Crypto.Generators.Poly1305KeyGenerator"/>
	public class Poly1305Mac
		: IMac
	{
		private const int BLOCK_SIZE = 16;

		private readonly IBlockCipher cipher;

		private readonly byte[] singleByte = new byte[1];

		// Initialised state

		/*		* Polynomial key */
		private uint r0, r1, r2, r3, r4;

		/*		* Precomputed 5 * r[1..4] */
		private uint s1, s2, s3, s4;

		/*		* Encrypted nonce */
		private uint k0, k1, k2, k3;

		// Accumulating state

		/*		* Current block of buffered input */
		private byte[] currentBlock = new byte[BLOCK_SIZE];

		/*		* Current offset in input buffer */
		private int currentBlockOffset = 0;

		/*		* Polynomial accumulator */
		private uint h0, h1, h2, h3, h4;

		/*		*
	     * Constructs a Poly1305 MAC, using a 128 bit block cipher.
	     */
		public Poly1305Mac(IBlockCipher cipher)
		{
			if (cipher.BlockSize != BLOCK_SIZE)
			{
				throw new ArgumentException("Poly1305 requires a 128 bit block cipher.");
			}
			this.cipher = cipher;
		}


		public int MacSize 
		{
			get { return BLOCK_SIZE; }
		}

		/// <summary>
		/// This initialisation method cannot be used. Do not call this method.
		/// </summary>
		/// <param name="key">Key.</param>
		public void Init (byte[] key) {
			throw new NotSupportedException ("An IV/nonce is required for Poly1305 initialisation.");
		}

		public void Init (byte[] key, byte[] iv) {
			InitInternal (key, iv, true);
		}

		public void InitWithExistingPoly1305Key (byte[] key, byte[] iv) {
			InitInternal (key, iv, false);
		}

		private void InitInternal (byte[] key, byte[] nonce, bool clamp) {
			if (key == null) {
				throw new ArgumentNullException ("key", "Poly1305 initialisation requires a key.");
			} else if (key.Length != 32) {
				throw new ArgumentException ("Poly1305 initialisation requires exactly 32 bytes of key.", "key");
			}
			if (nonce == null) {
				throw new InvalidOperationException ("Poly1305 initialisation requires a nonce/IV.");
			} else if (key.Length != 32) {
				throw new ArgumentException ("Poly1305 initialisation requires exactly 16 bytes of nonce/IV.", "key");
			}

			byte[] clampedKey;
			if (clamp) {
				clampedKey = ClampKey (key);
			} else {
				// Check key validity
				CheckKey (key);
				clampedKey = key;
			}

			SetKey (clampedKey, nonce);
			Reset ();
		}



		private void SetKey(byte[] key, byte[] nonce) {
			// Extract r portion of key
			uint t0 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 0);
			uint t1 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 4);
			uint t2 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 8);
			uint t3 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 12);

			r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
			r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
			r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
			r3 = t2 & 0x3f03fff; t3 >>= 8;
			r4 = t3 & 0x00fffff;

			// Precompute multipliers
			s1 = r1 * 5;
			s2 = r2 * 5;
			s3 = r3 * 5;
			s4 = r4 * 5;

			// Compute encrypted nonce
			byte[] cipherKey = new byte[BLOCK_SIZE];
			Array.Copy(key, 0, cipherKey, 0, cipherKey.Length);

			cipher.Init(true, cipherKey, null);
			cipher.ProcessBlock(nonce, 0, cipherKey, 0);

			k0 = Pack.LE_To_UInt32(cipherKey, 0);
			k1 = Pack.LE_To_UInt32(cipherKey, 4);
			k2 = Pack.LE_To_UInt32(cipherKey, 8);
			k3 = Pack.LE_To_UInt32(cipherKey, 12);
		}

		public string AlgorithmName
		{
			get { return "Poly1305-" + cipher.AlgorithmName; }
		}

		public void Update (byte input) {
			currentBlock [currentBlockOffset++] = input;
			if(currentBlockOffset == BLOCK_SIZE) {
				ProcessBlock (currentBlock, 0, false);
				currentBlockOffset = 0;
			}
		}

		public void BlockUpdate(byte[] input, int inOff, int len) {
			// Any left over from last time?
			if (currentBlockOffset > 0) {
				var required = BLOCK_SIZE - currentBlockOffset;
				if (required > len) {
					required = len;
				}
				Array.Copy (input, inOff, currentBlock, currentBlockOffset, required);
				currentBlockOffset += required;
				inOff += required;
				len -= required;
				if (currentBlockOffset == BLOCK_SIZE) {
					ProcessBlock (currentBlock, 0, false);
					currentBlockOffset = 0;
				}
			}

			int remainder;
			var blocks = Math.DivRem (len, BLOCK_SIZE, out remainder);

			for (var i = 0; i < blocks; i++) {
				ProcessBlock (input, inOff, false);
				inOff += BLOCK_SIZE;
			}

			if (remainder > 0) {
				Array.Copy (input, inOff, currentBlock, currentBlockOffset, remainder);
				currentBlockOffset = remainder;
			}
		}

		public int DoFinal(byte[] output, int outOff) {
			if (outOff + BLOCK_SIZE > output.Length) {
				throw new DataLengthException("Output buffer is too short.");
			}

			if (currentBlockOffset > 0) {
				// Padding of block required
				byte[] processingBlock = new byte[BLOCK_SIZE];
				Array.Copy (currentBlock, 0, processingBlock, 0, currentBlockOffset);
				processingBlock[currentBlockOffset] = 1;
				for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++) {
					processingBlock[i] = 0;
				}
				ProcessBlock (processingBlock, 0, true);
			}

			ulong f0, f1, f2, f3;

			uint b = h0 >> 26;
			h0 = h0 & 0x3ffffff;
			h1 += b; b = h1 >> 26; h1 = h1 & 0x3ffffff;
			h2 += b; b = h2 >> 26; h2 = h2 & 0x3ffffff;
			h3 += b; b = h3 >> 26; h3 = h3 & 0x3ffffff;
			h4 += b; b = h4 >> 26; h4 = h4 & 0x3ffffff;
			h0 += b * 5;

			uint g0, g1, g2, g3, g4;
			g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
			g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
			g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
			g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
			g4 = h4 + b - (1 << 26);

			b = (g4 >> 31) - 1;
			uint nb = ~b;
			h0 = (h0 & nb) | (g0 & b);
			h1 = (h1 & nb) | (g1 & b);
			h2 = (h2 & nb) | (g2 & b);
			h3 = (h3 & nb) | (g3 & b);
			h4 = (h4 & nb) | (g4 & b);

			f0 = ((h0      ) | (h1 << 26)) + (ulong)k0;
			f1 = ((h1 >> 6 ) | (h2 << 20)) + (ulong)k1;
			f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)k2;
			f3 = ((h3 >> 18) | (h4 << 8 )) + (ulong)k3;

			Pack.UInt32_To_LE((uint)f0, output, outOff);
			f1 += (f0 >> 32);
			Pack.UInt32_To_LE((uint)f1, output, outOff + 4);
			f2 += (f1 >> 32);
			Pack.UInt32_To_LE((uint)f2, output, outOff + 8);
			f3 += (f2 >> 32);
			Pack.UInt32_To_LE((uint)f3, output, outOff + 12);

			Reset();
			return BLOCK_SIZE;
		}

		public void Reset() {
			h0 = h1 = h2 = h3 = h4 = 0;
			currentBlockOffset = 0;
			Array.Clear (currentBlock, 0, currentBlock.Length);
		}

		private void ProcessBlock(byte[] block, int offset, bool padded) {
			ulong t0 = Pack.LE_To_UInt32(block, offset + 0);
			ulong t1 = Pack.LE_To_UInt32(block, offset + 4);
			ulong t2 = Pack.LE_To_UInt32(block, offset + 8);
			ulong t3 = Pack.LE_To_UInt32(block, offset + 12);

			h0 += (uint)(t0 & 0x3ffffffU);
			h1 += (uint)((((t1 << 32) | t0) >> 26) & 0x3ffffff);
			h2 += (uint)((((t2 << 32) | t1) >> 20) & 0x3ffffff);
			h3 += (uint)((((t3 << 32) | t2) >> 14) & 0x3ffffff);
			h4 += (uint)(t3 >> 8);

			if (padded == false) h4 += (1 << 24);

			ulong tp0 = mul32x32_64(h0,r0) + mul32x32_64(h1,s4) + mul32x32_64(h2,s3) + mul32x32_64(h3,s2) + mul32x32_64(h4,s1);
			ulong tp1 = mul32x32_64(h0,r1) + mul32x32_64(h1,r0) + mul32x32_64(h2,s4) + mul32x32_64(h3,s3) + mul32x32_64(h4,s2);
			ulong tp2 = mul32x32_64(h0,r2) + mul32x32_64(h1,r1) + mul32x32_64(h2,r0) + mul32x32_64(h3,s4) + mul32x32_64(h4,s3);
			ulong tp3 = mul32x32_64(h0,r3) + mul32x32_64(h1,r2) + mul32x32_64(h2,r1) + mul32x32_64(h3,r0) + mul32x32_64(h4,s4);
			ulong tp4 = mul32x32_64(h0,r4) + mul32x32_64(h1,r3) + mul32x32_64(h2,r2) + mul32x32_64(h3,r1) + mul32x32_64(h4,r0);

			ulong b;
			h0 = (uint)tp0 & 0x3ffffff; b = (tp0 >> 26);
			tp1 += b; h1 = (uint)tp1 & 0x3ffffff; b = (tp1 >> 26);
			tp2 += b; h2 = (uint)tp2 & 0x3ffffff; b = (tp2 >> 26);
			tp3 += b; h3 = (uint)tp3 & 0x3ffffff; b = (tp3 >> 26);
			tp4 += b; h4 = (uint)tp4 & 0x3ffffff; b = (tp4 >> 26);
			h0 += (uint)(b * 5);
		}

		private static ulong mul32x32_64 (uint i1, uint i2) {
			return ((ulong)i1) * i2;
		}

		/// <summary>
		/// Convert an existing 32 byte (256-bit) key to a Poly1305-format-compatible key. 
		/// Caution: Conversion is irreversible!
		/// </summary>
		/// <param name="key">Key to clamp (convert).</param>
		public static void ClampKeyInPlace (byte[] key) {
			if (key == null) {
				throw new ArgumentNullException ("key");
			} else if (key.Length != 32) {
				throw new ArgumentException("Poly1305 requires an exactly 32 byte (256 bit) key.", "key");
			}

			const byte R_MASK_LOW_2 = 0xFC;
			const byte R_MASK_HIGH_4 = 0x0F;

			// r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})
			key[19] &= R_MASK_HIGH_4;
			key[23] &= R_MASK_HIGH_4;
			key[27] &= R_MASK_HIGH_4;
			key[31] &= R_MASK_HIGH_4;

			// r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252}).
			key[20] &= R_MASK_LOW_2;
			key[24] &= R_MASK_LOW_2;
			key[28] &= R_MASK_LOW_2;
		}

		/// <summary>
		/// Convert an existing 32 byte (256-bit) key to a Poly1305-compatible key. 
		/// Does not modify existing key, but rather returns modified key.
		/// </summary>
		/// <param name="key">Key to clamp (convert).</param>
		/// <returns>Poly1305-compatible key.</returns>
		public static byte[] ClampKey (byte[] key) {
			byte[] clampedKey = new byte[key.Length];
			Array.Copy (key, clampedKey, key.Length);
			ClampKeyInPlace (clampedKey);
			return clampedKey;
		}

		/// <summary>
		/// Checks if key conforms to Poly1305 format.
		/// </summary>
		/// <param name="key">Key to check. Must be 32 bytes (256-bit).</param>
		public static void CheckKey (byte[] key) {
			const byte R_MASK_LOW_2 = 0xFC;
			const byte R_MASK_HIGH_4 = 0x0F;

			bool invalid = false;
			invalid |= (key [19] & ~R_MASK_HIGH_4) != 0;
			invalid |= (key [23] & ~R_MASK_HIGH_4) != 0;
			invalid |= (key [27] & ~R_MASK_HIGH_4) != 0;
			invalid |= (key [31] & ~R_MASK_HIGH_4) != 0;

			invalid |= (key [20] & ~R_MASK_LOW_2) != 0;
			invalid |= (key [24] & ~R_MASK_LOW_2) != 0;
			invalid |= (key [28] & ~R_MASK_LOW_2) != 0;

			if (invalid) {
				throw new ArgumentException ("Key is invalid.", "key");
			}
		}
	}


//	public class Poly1305Mac : IMac
//	{
//		private const int BlockSize = 16;
//
//		private readonly IBlockCipher _cipher;
//
//		private readonly byte[] _blockBuffer = new byte[BlockSize];
//		private int _blockBufferOffset;
//
//		private UInt32 k0, k1, k2, k3; // [encrypted] iv/nonce
//		private UInt32 s1, s2, s3, s4; // precomputed 5 * r0-through-4
//		private UInt32 r0, r1, r2, r3, r4; // polynomial key
//		private UInt32 h0, h1, h2, h3, h4; // polynomial accumulator
//
//		/// <summary>
//		/// Initializes a new instance of a Poly1305 MAC primitive. 
//		/// Uses a block cipher to derive a authentication nonce. 
//		/// When used with AES, for example, the primitive becomes Poly1305-AES.
//		/// </summary>
//		/// <param name="cipher">Cipher used in deriving an IV/nonce.</param>
//		public Poly1305Mac (IBlockCipher cipher)
//		{
//			if (cipher.BlockSize != BlockSize) {
//				throw new ArgumentException ("Cipher must have a 128-bit block size.", "cipher");
//			}
//			_cipher = cipher;
//		}
//
//		public string AlgorithmName 
//		{
//			get { return "Poly1305-" + _cipher.AlgorithmName; }
//		}
//
//		public int MacSize 
//		{
//			get { return BlockSize; }
//		}
//
//		public void Init (byte[] key) {
//			throw new NotSupportedException ("An IV/nonce is required for Poly1305 initialisation.");
//		}
//
//		public void Init (byte[] key, byte[] iv) {
//			InitInternal (key, iv, true);
//		}
//
//		public void InitWithExistingPoly1305Key (byte[] key, byte[] iv) {
//			InitInternal (key, iv, false);
//		}
//
//		private void InitInternal (byte[] key, byte[] iv, bool clamp) {
//			if (key == null)
//				throw new ArgumentNullException ("key", "Poly1305 initialisation requires a key.");
//			if(key.Length != 32) 
//				throw new ArgumentException("Poly1305 initialisation requires exactly 32 bytes of key.", "key");
//
//			if (iv == null) {
//				throw new InvalidOperationException ("Poly1305 initialisation requires an IV/nonce.");
//			} else if (key.Length != 32) {
//				throw new ArgumentException ("Poly1305 initialisation requires exactly 16 bytes of IV/nonce.", "key");
//			}
//
//			byte[] clampedKey;
//			if (clamp) {
//				clampedKey = ClampKey (key);
//			} else {
//				// Check key validity
//				CheckKey (key);
//				clampedKey = key;
//			}
//
//			// Extract r portion of key
//			uint t0 = clampedKey.LittleEndianToUInt32 (BlockSize + 0);
//			uint t1 = clampedKey.LittleEndianToUInt32 (BlockSize + 4);
//			uint t2 = clampedKey.LittleEndianToUInt32 (BlockSize + 8);
//			uint t3 = clampedKey.LittleEndianToUInt32 (BlockSize + 12);
//
//			r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
//			r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
//			r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
//			r3 = t2 & 0x3f03fff; t3 >>= 8;
//			r4 = t3 & 0x00fffff;
//
//			// Precompute multipliers
//			s1 = r1 * 5;
//			s2 = r2 * 5;
//			s3 = r3 * 5;
//			s4 = r4 * 5;
//
//			// Compute encrypted nonce
//			byte[] cipherKey = new byte[BlockSize];
//			Array.Copy(clampedKey, 0, cipherKey, 0, cipherKey.Length);
//			_cipher.Init(true, cipherKey, null);
//			_cipher.ProcessBlock (iv, 0, cipherKey, 0);
//
//			k0 = cipherKey.LittleEndianToUInt32 (0);
//			k1 = cipherKey.LittleEndianToUInt32 (4);
//			k2 = cipherKey.LittleEndianToUInt32 (8);
//			k3 = cipherKey.LittleEndianToUInt32 (12);
//
//			Reset ();
//		}
//
//		private void Precompute (byte[] key) {
//
//		}
//
//		/// <summary>
//		/// Convert an existing 256-bit key to a Poly1305-compatible key. 
//		/// Caution: Conversion is irreversible!
//		/// </summary>
//		/// <param name="key">Key to clamp (convert).</param>
//		public static void ClampKeyInPlace (byte[] key) {
//			if (key.Length != 32) {
//				throw new ArgumentException("Poly1305 key must be 32 bytes (256 bits).", "key");
//			}
//
//			const byte R_MASK_LOW_2 = 0xFC;
//			const byte R_MASK_HIGH_4 = 0x0F;
//
//			// r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})
//			key[19] &= R_MASK_HIGH_4;
//			key[23] &= R_MASK_HIGH_4;
//			key[27] &= R_MASK_HIGH_4;
//			key[31] &= R_MASK_HIGH_4;
//
//			// r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252}).
//			key[20] &= R_MASK_LOW_2;
//			key[24] &= R_MASK_LOW_2;
//			key[28] &= R_MASK_LOW_2;
//		}
//
//		/// <summary>
//		/// Convert an existing 256-bit key to a Poly1305-compatible key. 
//		/// </summary>
//		/// <param name="key">Key to clamp (convert).</param>
//		/// <returns>Poly1305-compatible key.</returns>
//		public static byte[] ClampKey (byte[] key) {
//			var clampedKey = new byte[key.Length];
//			Array.Copy (key, clampedKey, key.Length);
//
//			ClampKeyInPlace (clampedKey);
//
//			return clampedKey;
//		}
//
//		public static void CheckKey (byte[] key) {
//			const byte R_MASK_LOW_2 = 0xFC;
//			const byte R_MASK_HIGH_4 = 0x0F;
//
//			bool invalid = false;
//			invalid |= (key [19] & ~R_MASK_HIGH_4) != 0;
//			invalid |= (key [23] & ~R_MASK_HIGH_4) != 0;
//			invalid |= (key [27] & ~R_MASK_HIGH_4) != 0;
//			invalid |= (key [31] & ~R_MASK_HIGH_4) != 0;
//
//			invalid |= (key [20] & ~R_MASK_LOW_2) != 0;
//			invalid |= (key [24] & ~R_MASK_LOW_2) != 0;
//			invalid |= (key [28] & ~R_MASK_LOW_2) != 0;
//
//			if(invalid) {
//				throw new ArgumentException ("Key is invalid.", "key");
//			}
//		}
//
//		public void Update (byte input) {
//			_blockBuffer [_blockBufferOffset++] = input;
//			if(_blockBufferOffset == BlockSize) {
//				DoBlock (_blockBuffer, 0, false);
//				_blockBufferOffset = 0;
//			}
//		}
//
//		public void BlockUpdate (byte[] input, int inOff, int len) {
//			// Any left over from last time?
//			if(_blockBufferOffset > 0) {
//				int required = BlockSize - _blockBufferOffset;
//				if(required > len) {
//					required = len;
//				}
//
//				Array.Copy (input, inOff, _blockBuffer, _blockBufferOffset, required);
//				_blockBufferOffset += required;
//				len = -required;
//				if (_blockBufferOffset == BlockSize) {
//					DoBlock (_blockBuffer, 0, false);
//					_blockBufferOffset = 0;
//				}
//			}
//			// Process all the whole blocks
//			while (len >= 16) {
//				DoBlock (input, inOff, false);
//				inOff += 16;
//				len -= 16;
//			}
//			// Any left?
//			if (len > 0) {
//				Array.Copy (input, inOff, _blockBuffer, _blockBufferOffset, len);
//				_blockBufferOffset += len;
//			}
//		}
//
//		/// <summary>
//		/// Process a whole 16 byte block.
//		/// </summary>
//		/// <param name="m">Input message.</param>
//		/// <param name="mStart">Input message offset.</param>
//		private void DoBlock(byte[] m, int mStart, bool final) {
//			long t0 = 0xffffffffL & m.LittleEndianToUInt32 (0);
//			long t1 = 0xffffffffL & m.LittleEndianToUInt32 (4);
//			long t2 = 0xffffffffL & m.LittleEndianToUInt32 (8);
//			long t3 = 0xffffffffL & m.LittleEndianToUInt32 (12);
//
//			h0 += (uint)t0 & 0x3ffffff;
//			h1 += (uint)(((t1 << 32) | t0) >> 26) & 0x3ffffff;
//			h2 += (uint)(((t2 << 32) | t1) >> 20) & 0x3ffffff;
//			h3 += (uint)(((t3 << 32) | t2) >> 14) & 0x3ffffff;
//			h4 += (uint)(t3 >> 8);
//			if(final) {
//				h4 += (1 << 24);
//			}
//
//			ulong tp0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
//			ulong tp1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
//			ulong tp2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
//			ulong tp3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
//			ulong tp4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;
//
//			ulong b, c;
//			h0 = (uint)tp0 & 0x3ffffff; c = (tp0 >> 26);
//			tp1 += c; h1 = (uint)tp1 & 0x3ffffff; b = (uint)(tp1 >> 26);
//			tp2 += b; h2 = (uint)tp2 & 0x3ffffff; b = (uint)(tp2 >> 26);
//			tp3 += b; h3 = (uint)tp3 & 0x3ffffff; b = (uint)(tp3 >> 26);
//			tp4 += b; h4 = (uint)tp4 & 0x3ffffff; b = (uint)(tp4 >> 26);
//			h0 += (uint)(b * 5);
//		}
//
//		public int DoFinal (byte[] output, int outOff) {
//			if(_blockBufferOffset < BlockSize) {
//				_blockBuffer[_blockBufferOffset++] = 1;
//				// Zero out rest of block
//				for (int i = _blockBufferOffset; i < BlockSize; i++) {
//					_blockBuffer[i] = 0;
//				}
//				DoBlock (_blockBuffer, 0, true);
//			}
//
//			ulong f0, f1, f2, f3;
//			uint g0, g1, g2, g3, g4;
//
//			uint b = h0 >> 26; h0 = h0 & 0x3ffffff;
//			h1 += b; b = h1 >> 26; h1 &= 0x3ffffff;
//			h2 += b; b = h2 >> 26; h2 &= 0x3ffffff;
//			h3 += b; b = h3 >> 26; h3 &= 0x3ffffff;
//			h4 += b; b = h4 >> 26; h4 &= 0x3ffffff;
//			h0 += b * 5;
//
//			g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
//			g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
//			g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
//			g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
//			g4 = h4 + b - (1 << 26);
//
//			b = (g4 >> 31) - 1;
//			uint nb = ~b;
//			h0 = (h0 & nb) | (g0 & b);
//			h1 = (h1 & nb) | (g1 & b);
//			h2 = (h2 & nb) | (g2 & b);
//			h3 = (h3 & nb) | (g3 & b);
//			h4 = (h4 & nb) | (g4 & b);
//
//			f0 = ((h0) | (h1 << 26)) + (ulong)k0;
//			f1 = ((h1 >> 6) | (h2 << 20)) + (ulong)k1;
//			f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)k2;
//			f3 = ((h3 >> 18) | (h4 << 8)) + (ulong)k3;
//
//			((uint)f0).ToLittleEndian (output, outOff + 0); f1 += (f0 >> 32);
//			((uint)f1).ToLittleEndian (output, outOff + 4); f2 += (f1 >> 32);
//			((uint)f2).ToLittleEndian (output, outOff + 8); f3 += (f2 >> 32);
//			((uint)f3).ToLittleEndian (output, outOff + 12);
//
//			Reset ();
//			return BlockSize;
//		}
//
//		public void Reset () {
//			h0 = 0;
//			h1 = 0;
//			h2 = 0;
//			h3 = 0;
//			h4 = 0;
//
//			Array.Clear (_blockBuffer, 0, _blockBuffer.Length);
//			_blockBufferOffset = 0;
//		}
//	}
}

