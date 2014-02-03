//
//  Copyright 2014  Matthew Ducker
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

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	/// <summary>
	/// Variant of Salsa20 with a extended nonce (192 bit versus 64) for greater security.
	/// </summary>
	public class XSalsa20Engine : Salsa20Engine
	{
		public XSalsa20Engine (int rounds = DEFAULT_ROUNDS) : base(rounds)
		{	
			CipherName = "XSalsa20";
		}

		public override void Init (bool encrypting, byte[] key, byte[] iv) {
			if (iv == null) 
				throw new ArgumentNullException("iv", "XSalsa20 initialisation requires an IV.");
			else if (iv.Length != 24)
				throw new ArgumentException("XSalsa20 requires exactly 24 bytes of IV.", "iv");

			if (key == null) 
				throw new ArgumentNullException("key", "XSalsa20 initialisation requires a key.");
			else if (key.Length != 16 && key.Length != 32) {
				throw new ArgumentException ("XSalsa20 requires a 16 or 32 byte key.", "key");
			}

			SetKey(key, iv);
			Reset ();
			initialised = true;
		}

		protected override void SetKey (byte[] keyBytes, byte[] ivBytes) {
			PrepareHSalsaBlock (engineState, keyBytes, ivBytes);
			var hsalsa20Out = new uint[engineState.Length];
			HSalsaCore(rounds, engineState, 0, hsalsa20Out, 0);

			engineState[1] = hsalsa20Out[0];
			engineState[2] = hsalsa20Out[5];
			engineState[3] = hsalsa20Out[10];
			engineState[4] = hsalsa20Out[15];

			engineState[11] = hsalsa20Out[6];
			engineState[12] = hsalsa20Out[7];
			engineState[13] = hsalsa20Out[8];
			engineState[14] = hsalsa20Out[9];

			engineState[6] = Pack.LE_To_UInt32(ivBytes, 16);
			engineState[7] = Pack.LE_To_UInt32(ivBytes, 20);

			ResetCounter();
		}

		internal static uint[] PrepareHSalsaBlock(byte[] key, byte[] nonce) {
			uint[] state = new uint[16];
			PrepareHSalsaBlock (state, key, nonce);
			return state;
		}

		internal static void PrepareHSalsaBlock(uint[] state, byte[] key, byte[] nonce) {
			int offset = 0;
			byte[] constants;

			if (key.Length == 32) {
				constants = Sigma;
				offset = 16;
			} else {
				constants = Tau;
			}

			state[0]  = Pack.LE_To_UInt32(constants, 0);
			state[1]  = Pack.LE_To_UInt32(key, 0);
			state[2]  = Pack.LE_To_UInt32(key, 4);
			state[3]  = Pack.LE_To_UInt32(key, 8);
			state[4]  = Pack.LE_To_UInt32(key, 12);
			state[5]  = Pack.LE_To_UInt32(constants, 4);
			state[6]  = Pack.LE_To_UInt32(nonce, 0);
			state[7]  = Pack.LE_To_UInt32(nonce, 4);
			state[8]  = Pack.LE_To_UInt32(nonce, 8);
			state[9]  = Pack.LE_To_UInt32(nonce, 12);
			state[10] = Pack.LE_To_UInt32(constants, 8);
			state[11] = Pack.LE_To_UInt32(key, offset + 0);
			state[12] = Pack.LE_To_UInt32(key, offset + 4);
			state[13] = Pack.LE_To_UInt32(key, offset + 8);
			state[14] = Pack.LE_To_UInt32(key, offset + 12);
			state[15] = Pack.LE_To_UInt32(constants, 12);
		}

		internal static void HSalsa20(byte[] output, int outputOffset, byte[] key, byte[] nonce) {
			var block = XSalsa20Engine.PrepareHSalsaBlock (key, nonce);
			XSalsa20Engine.HSalsaCore (20, block, 0, block, 0);

			Pack.UInt32_To_LE(block[0],  output, outputOffset + 0);
			Pack.UInt32_To_LE(block[5],  output, outputOffset + 4);
			Pack.UInt32_To_LE(block[10], output, outputOffset + 8);
			Pack.UInt32_To_LE(block[15], output, outputOffset + 12);
			Pack.UInt32_To_LE(block[6],  output, outputOffset + 16);
			Pack.UInt32_To_LE(block[7],  output, outputOffset + 20);
			Pack.UInt32_To_LE(block[8],  output, outputOffset + 24);
			Pack.UInt32_To_LE(block[9],  output, outputOffset + 28);
		}

		internal static void HSalsaCore(int rounds, uint[] input, int inOff, uint[] x, int xOff) {
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
			uint x10 = input[inOff +10];
			uint x11 = input[inOff +11];
			uint x12 = input[inOff +12];
			uint x13 = input[inOff +13];
			uint x14 = input[inOff +14];
			uint x15 = input[inOff +15];

			for (int i = rounds; i > 0; i -= 2) {
				x04 ^= R((x00+x12), 7);
				x08 ^= R((x04+x00), 9);
				x12 ^= R((x08+x04),13);
				x00 ^= R((x12+x08),18);
				x09 ^= R((x05+x01), 7);
				x13 ^= R((x09+x05), 9);
				x01 ^= R((x13+x09),13);
				x05 ^= R((x01+x13),18);
				x14 ^= R((x10+x06), 7);
				x02 ^= R((x14+x10), 9);
				x06 ^= R((x02+x14),13);
				x10 ^= R((x06+x02),18);
				x03 ^= R((x15+x11), 7);
				x07 ^= R((x03+x15), 9);
				x11 ^= R((x07+x03),13);
				x15 ^= R((x11+x07),18);

				x01 ^= R((x00+x03), 7);
				x02 ^= R((x01+x00), 9);
				x03 ^= R((x02+x01),13);
				x00 ^= R((x03+x02),18);
				x06 ^= R((x05+x04), 7);
				x07 ^= R((x06+x05), 9);
				x04 ^= R((x07+x06),13);
				x05 ^= R((x04+x07),18);
				x11 ^= R((x10+x09), 7);
				x08 ^= R((x11+x10), 9);
				x09 ^= R((x08+x11),13);
				x10 ^= R((x09+x08),18);
				x12 ^= R((x15+x14), 7);
				x13 ^= R((x12+x15), 9);
				x14 ^= R((x13+x12),13);
				x15 ^= R((x14+x13),18);
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
			x[xOff +10] = x10;
			x[xOff +11] = x11;
			x[xOff +12] = x12;
			x[xOff +13] = x13;
			x[xOff +14] = x14;
			x[xOff +15] = x15;
		}
	}
}

