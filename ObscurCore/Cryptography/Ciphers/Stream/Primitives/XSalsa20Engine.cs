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
using ObscurCore.Extensions.BitPacking;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	/// <summary>
	/// Variant of Salsa20 with a extended nonce (192 bit versus 64) for greater security.
	/// </summary>
	public class XSalsa20Engine : Salsa20Engine
	{
		public XSalsa20Engine (int rounds = DEFAULT_ROUNDS) : base(rounds)
		{	
		}


		public override void Init (bool encrypting, byte[] key, byte[] iv) {
			if (iv == null) 
				throw new ArgumentNullException("iv", "XSalsa20 initialisation requires an IV.");
			if (iv.Length != 24)
				throw new ArgumentException("XSalsa20 requires exactly 24 bytes of IV.", "iv");

			if (key == null) 
				throw new ArgumentNullException("key", "XSalsa20 initialisation requires a key.");
			else if (key.Length != 16 && key.Length != 32) {
				throw new ArgumentException ("XSalsa20 requires a 16 or 32 byte key.", "key");
			}

			SetKey(key, iv);
		}

		protected override void SetKey (byte[] keyBytes, byte[] ivBytes) {
			// Set key for HSalsa20
			base.SetKey (keyBytes, ivBytes);

			// Pack next 64 bits of IV into engine state instead of counter
			_engineState[8] = ivBytes.LittleEndianToInt32(8);
			_engineState[9] = ivBytes.LittleEndianToInt32(12);

			// Process engine state to generate Salsa20 key
			int[] hsalsa20Out = new int[_engineState.Length];
			base.SalsaCore(_rounds, _engineState, hsalsa20Out);

			// Set new key, removing addition in last round of salsaCore
			_engineState[1] = hsalsa20Out[0] - _engineState[0];
			_engineState[2] = hsalsa20Out[5] - _engineState[5];
			_engineState[3] = hsalsa20Out[10] - _engineState[10];
			_engineState[4] = hsalsa20Out[15] - _engineState[15];

			_engineState[11] = hsalsa20Out[6] - _engineState[6];
			_engineState[12] = hsalsa20Out[7] - _engineState[7];
			_engineState[13] = hsalsa20Out[8] - _engineState[8];
			_engineState[14] = hsalsa20Out[9] - _engineState[9];

			// Last 64 bits of input IV
			_engineState[6] = ivBytes.LittleEndianToInt32(16);
			_engineState[7] = ivBytes.LittleEndianToInt32(20);
		}
	}
}

