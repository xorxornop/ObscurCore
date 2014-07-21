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
	/// Variant of Salsa20 with a extended nonce for greater security.
	/// </summary>
	public class XSalsa20Engine : Salsa20Engine
	{
		public XSalsa20Engine (int rounds = DefaultRounds) : base(rounds)
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
			Initialised = true;
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
	}
}
