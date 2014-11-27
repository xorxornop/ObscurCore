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
using Obscur.Core.Cryptography.Support;

namespace Obscur.Core.Cryptography.Ciphers.Stream.Primitives
{
	/// <summary>
	///     XSalsa20 stream cipher implementation.
	/// </summary>
    /// <remarks>
    ///     A variant of Salsa20 with a extended nonce for greater security.
    /// </remarks>
	public class XSalsa20Engine : Salsa20Engine
	{
		public XSalsa20Engine (int rounds = DefaultRounds) : base(StreamCipher.XSalsa20, rounds)
		{	
			CipherName = "XSalsa20";
		}

	    protected override void SetKey (byte[] keyBytes, byte[] ivBytes) {
			PrepareHSalsaBlock (EngineState, keyBytes, ivBytes);
			var hsalsa20Out = new uint[EngineState.Length];
			HSalsa(Rounds, EngineState, 0, hsalsa20Out, 0);

			EngineState[1] = hsalsa20Out[0];
			EngineState[2] = hsalsa20Out[5];
			EngineState[3] = hsalsa20Out[10];
			EngineState[4] = hsalsa20Out[15];

			EngineState[11] = hsalsa20Out[6];
			EngineState[12] = hsalsa20Out[7];
			EngineState[13] = hsalsa20Out[8];
			EngineState[14] = hsalsa20Out[9];

			EngineState[6] = Pack.LE_To_UInt32(ivBytes, 16);
			EngineState[7] = Pack.LE_To_UInt32(ivBytes, 20);

			ResetCounter();
		}

	    protected internal static void HSalsa20(byte[] output, int outputOffset, byte[] key, byte[] nonce)
	    {
	        var block = PrepareHSalsaBlock(key, nonce);
	        HSalsa(20, block, 0, block, 0);

	        Pack.UInt32_To_LE((uint) block[0], output, outputOffset + 0);
	        Pack.UInt32_To_LE((uint) block[5], output, outputOffset + 4);
	        Pack.UInt32_To_LE((uint) block[10], output, outputOffset + 8);
	        Pack.UInt32_To_LE((uint) block[15], output, outputOffset + 12);
	        Pack.UInt32_To_LE((uint) block[6], output, outputOffset + 16);
	        Pack.UInt32_To_LE((uint) block[7], output, outputOffset + 20);
	        Pack.UInt32_To_LE((uint) block[8], output, outputOffset + 24);
	        Pack.UInt32_To_LE((uint) block[9], output, outputOffset + 28);
	    }


	    internal static uint[] PrepareHSalsaBlock(byte[] key, byte[] nonce)
	    {
	        uint[] state = new uint[16];
	        PrepareHSalsaBlock(state, key, nonce);
	        return state;
	    }

	    protected internal static void PrepareHSalsaBlock(uint[] state, byte[] key, byte[] nonce)
	    {
	        int offset = 0;
	        byte[] constants;

	        if (key.Length == 32) {
	            constants = Sigma;
	            offset = 16;
	        } else {
	            constants = Tau;
	        }

	        state[0] = Pack.LE_To_UInt32(constants, 0);
	        state[1] = Pack.LE_To_UInt32(key, 0);
	        state[2] = Pack.LE_To_UInt32(key, 4);
	        state[3] = Pack.LE_To_UInt32(key, 8);
	        state[4] = Pack.LE_To_UInt32(key, 12);
	        state[5] = Pack.LE_To_UInt32(constants, 4);
	        state[6] = Pack.LE_To_UInt32(nonce, 0);
	        state[7] = Pack.LE_To_UInt32(nonce, 4);
	        state[8] = Pack.LE_To_UInt32(nonce, 8);
	        state[9] = Pack.LE_To_UInt32(nonce, 12);
	        state[10] = Pack.LE_To_UInt32(constants, 8);
	        state[11] = Pack.LE_To_UInt32(key, offset + 0);
	        state[12] = Pack.LE_To_UInt32(key, offset + 4);
	        state[13] = Pack.LE_To_UInt32(key, offset + 8);
	        state[14] = Pack.LE_To_UInt32(key, offset + 12);
	        state[15] = Pack.LE_To_UInt32(constants, 12);
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

#if INCLUDE_UNSAFE
        protected internal unsafe static void HSalsaUnsafe(int rounds, uint* input, uint* x)
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

            x[0] = x00;
            x[1] = x01;
            x[2] = x02;
            x[3] = x03;
            x[4] = x04;
            x[5] = x05;
            x[6] = x06;
            x[7] = x07;
            x[8] = x08;
            x[9] = x09;
            x[10] = x10;
            x[11] = x11;
            x[12] = x12;
            x[13] = x13;
            x[14] = x14;
            x[15] = x15;
        }
#endif
	}
}
