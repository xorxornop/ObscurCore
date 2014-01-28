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
			// Set key for HSalsa20
			base.SetKey (keyBytes, ivBytes);

			// Pack next 64 bits of IV into engine state instead of counter
			engineState[8] = ivBytes.LittleEndianToUInt32(8);
			engineState[9] = ivBytes.LittleEndianToUInt32(12);

			// Process engine state to generate Salsa20 key
			var hsalsa20Out = new uint[engineState.Length];
			SalsaCore(rounds, engineState, hsalsa20Out);

			// Set new key, removing addition in last round of salsaCore
			engineState[1] = hsalsa20Out[0] - engineState[0];
			engineState[2] = hsalsa20Out[5] - engineState[5];
			engineState[3] = hsalsa20Out[10] - engineState[10];
			engineState[4] = hsalsa20Out[15] - engineState[15];

			engineState[11] = hsalsa20Out[6] - engineState[6];
			engineState[12] = hsalsa20Out[7] - engineState[7];
			engineState[13] = hsalsa20Out[8] - engineState[8];
			engineState[14] = hsalsa20Out[9] - engineState[9];

			// Last 64 bits of input IV
			engineState[6] = ivBytes.LittleEndianToUInt32(16);
			engineState[7] = ivBytes.LittleEndianToUInt32(20);

			ResetCounter();
		}
	}
}

