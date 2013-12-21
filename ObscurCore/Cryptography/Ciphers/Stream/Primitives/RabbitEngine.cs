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
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support;
using ObscurCore.Extensions.BitPacking;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	public sealed class RabbitEngine : IStreamCipher, ICsprngCompatible
    {
        // Stores engine state
        private byte[]          _workingKey,
                                _workingIV;

        private bool	        _initialised;
		private readonly uint[] _state 			= new uint[8],
								_counter  		= new uint[8];
		private uint 			_counterArray;

		private byte[] 			_keyStream 		= new byte[16];
		private int 			_keyStreamPtr 	= 16;

		private readonly uint[] constants = new uint[] 	{ 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
                                                          0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3 };

        public void Init (bool forEncryption, ICipherParameters parameters) {
            // forEncryption parameter is irrelevant for Rabbit as operations are symmetrical, 
            // but required by class interface

            var ivParams = parameters as ParametersWithIV;
            if (ivParams == null) throw new ArgumentException("Rabbit initialisation requires an IV.", "parameters");
            _workingIV = ivParams.GetIV();
            if (_workingIV == null || _workingIV.Length != 8)
                throw new ArgumentException("Rabbit requires exactly 8 bytes of IV.");

            var key = ivParams.Parameters as KeyParameter;
            if (key == null) throw new ArgumentException("Rabbit initialisation requires a key.", "parameters");
            _workingKey = key.GetKey();
            if (_workingKey.Length != 16) throw new ArgumentException("Rabbit requires exactly 16 bytes of key.", "parameters");

            Reset();
        }

        public string AlgorithmName {
            get { return "Rabbit"; }
        }

		public int StateSize
		{
			get { return 16; }
		}

        public void Reset () {
            KeySetup(_workingKey);
            IVSetup(_workingIV);
            _initialised = true;
			Array.Clear (_keyStream, 0, 16);
			_keyStreamPtr = 16;
        }

        public byte ReturnByte (byte input) {
            //if (limitExceeded()) {
            //throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
            //}
            if (!_initialised) throw new InvalidOperationException(AlgorithmName + " not initialised.");

			if(_keyStreamPtr == 16) {
				NextState();
				Pack.UInt32_To_LE((_state[0] ^ (_state[5] >> 16) ^ (_state[3] << 16)), _keyStream, 0);
				Pack.UInt32_To_LE((_state[2] ^ (_state[7] >> 16) ^ (_state[5] << 16)), _keyStream, 4);
				Pack.UInt32_To_LE((_state[4] ^ (_state[1] >> 16) ^ (_state[7] << 16)), _keyStream, 8);
				Pack.UInt32_To_LE((_state[6] ^ (_state[3] >> 16) ^ (_state[1] << 16)), _keyStream, 12);
			}
			return _keyStream [_keyStreamPtr++];
        }

        public void ProcessBytes (byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff) {
            if (!_initialised) {
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
			} else if ((inOff + len) > inBytes.Length) {
				throw new ArgumentException("Input buffer too short.");
			} else if ((outOff + len) > outBytes.Length) {
				throw new ArgumentException("Output buffer too short.");
            }

            //if (limitExceeded(len)) {
            //throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
            //}

			if (len == 0)
				return;

			if(_keyStreamPtr < 16) {
				int blockLength = 16 - _keyStreamPtr;
				if (blockLength > len) {
					blockLength = len;
				}
				for (int i = 0; i < blockLength; i++) {
					outBytes [outOff + i] = (byte)(_keyStream [_keyStreamPtr + i] ^ inBytes [inOff]);
				}
				_keyStreamPtr += blockLength;
				inOff += blockLength;
				outOff += blockLength;
				len -= blockLength;
			}

			if (len == 0)
				return;

			int truncatedLen;
			var blocks = Math.DivRem(len, 16, out truncatedLen);
			for (var i = 0; i < blocks; i++) {
				NextState();
				Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff) ^ _state[0] ^ (_state[5] >> 16) ^ (_state[3] << 16), outBytes, outOff);
				Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 4) ^ _state[2] ^ (_state[7] >> 16) ^ (_state[5] << 16), outBytes, outOff + 4);
				Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 8) ^ _state[4] ^ (_state[1] >> 16) ^ (_state[7] << 16), outBytes, outOff + 8);
				Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 12) ^ _state[6] ^ (_state[3] >> 16) ^ (_state[1] << 16), outBytes, outOff + 12);
				inOff += 16;
				outOff += 16;
			}
			if (truncatedLen == 0) return;

			NextState();
			Pack.UInt32_To_LE((_state[0] ^ (_state[5] >> 16) ^ (_state[3] << 16)), _keyStream, 0);
			Pack.UInt32_To_LE((_state[2] ^ (_state[7] >> 16) ^ (_state[5] << 16)), _keyStream, 4);
			Pack.UInt32_To_LE((_state[4] ^ (_state[1] >> 16) ^ (_state[7] << 16)), _keyStream, 8);
			Pack.UInt32_To_LE((_state[6] ^ (_state[3] >> 16) ^ (_state[1] << 16)), _keyStream, 12);
			for (int i = 0; i < truncatedLen; i++) {
				outBytes[outOff + i] = (byte) (inBytes[inOff + i] ^ _keyStream[i]);
			}
			_keyStreamPtr = truncatedLen;
        }

		public void GetKeystream(byte[] buffer, int offset, int length) {
			if(_keyStreamPtr < 16) {
				int blockLength = 16 - _keyStreamPtr;
				if (blockLength > length) {
					blockLength = length;
				}
				Array.Copy(_keyStream, _keyStreamPtr, buffer, offset, blockLength);
				_keyStreamPtr += blockLength;
				offset += blockLength;
				length -= blockLength;
			}

			while (length >= 16) {
				NextState();
				Pack.UInt32_To_LE((_state[0] ^ (_state[5] >> 16) ^ (_state[3] << 16)), _keyStream, 0);
				Pack.UInt32_To_LE((_state[2] ^ (_state[7] >> 16) ^ (_state[5] << 16)), _keyStream, 4);
				Pack.UInt32_To_LE((_state[4] ^ (_state[1] >> 16) ^ (_state[7] << 16)), _keyStream, 8);
				Pack.UInt32_To_LE((_state[6] ^ (_state[3] >> 16) ^ (_state[1] << 16)), _keyStream, 12);
				offset += 16;
				length -= 16;
			}
			if(length > 0) {
				NextState();
				Pack.UInt32_To_LE((_state[0] ^ (_state[5] >> 16) ^ (_state[3] << 16)), _keyStream, 0);
				Pack.UInt32_To_LE((_state[2] ^ (_state[7] >> 16) ^ (_state[5] << 16)), _keyStream, 4);
				Pack.UInt32_To_LE((_state[4] ^ (_state[1] >> 16) ^ (_state[7] << 16)), _keyStream, 8);
				Pack.UInt32_To_LE((_state[6] ^ (_state[3] >> 16) ^ (_state[1] << 16)), _keyStream, 12);
				Array.Copy(_keyStream, 0, buffer, offset, length);
				_keyStreamPtr = length;
			}
		}

        #region Private implementation

        /// <summary>
        /// Initialise the engine state with key material.
        /// </summary>
        private void KeySetup (byte[] key) {
            var k = new uint[4];

            // Generate four subkeys
            k[0] = BitConverter.ToUInt32(key, 0);
            k[1] = BitConverter.ToUInt32(key, 4);
            k[2] = BitConverter.ToUInt32(key, 8);
            k[3] = BitConverter.ToUInt32(key, 12);

            // Generate initial state variables
            _state[0] = k[0];
            _state[2] = k[1];
            _state[4] = k[2];
            _state[6] = k[3];
            _state[1] = (k[3] << 16) | (k[2] >> 16);
            _state[3] = (k[0] << 16) | (k[3] >> 16);
            _state[5] = (k[1] << 16) | (k[0] >> 16);
            _state[7] = (k[2] << 16) | (k[1] >> 16);

            // Generate initial counter values
            _counter[0] = RotLeft(k[2], 16);
            _counter[2] = RotLeft(k[3], 16);
            _counter[4] = RotLeft(k[0], 16);
            _counter[6] = RotLeft(k[1], 16);
            _counter[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF);
            _counter[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF);
            _counter[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF);
            _counter[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF);

            // Clear carry bit
            _counterArray = 0;

            // Iterate the system four times
            for (var j = 0; j < 4; j++) NextState();

            // Iterate the counters
            for (var j = 0; j < 8; j++) _counter[j] ^= _state[(j + 4) & 0x7];
        }

        /// <summary>
        /// Initialise the engine state with initialisation vector material.
        /// </summary>
        private void IVSetup (byte[] iv) {
            if (iv.Length != 8) throw new ArgumentException("IV must be 8 bytes in length.");
            var i = new uint[4];

            // Generate four subvectors
            i[0] = BitConverter.ToUInt32(iv, 0);
            i[2] = BitConverter.ToUInt32(iv, 4);
            i[1] = (i[0] << 16) | (i[2] & 0xFFFF0000);
            i[3] = (i[2] << 16) | (i[0] & 0x0000FFFF);

            // Modify counter values
            var subIndex = 0;
            for (var index = 0; index < 8; index++) {
                _counter[index] ^= i[subIndex];
                if (++subIndex > 3) subIndex = 0;
            }

            // Iterate the system four times
			NextState();
			NextState();
			NextState();
			NextState();
        }

        private static uint RotLeft (uint state, int rot) {
            return (state << rot) | (state >> (32 - rot));
        }

        private void NextState () {
            // Temporary variables
            uint[] g = new uint[8], cOld = new uint[8];

            /* Save old counter values */
            for (var i = 0; i < 8; i++) cOld[i] = _counter[i];

            /* Calculate new counter values */
            _counter[0] += constants[0] + _counterArray;
            for (var i = 1; i < 8; i++) {
                _counter[i] += constants[i] + Convert.ToUInt32(_counter[i - 1] < cOld[i - 1]);
            }
            _counterArray = Convert.ToUInt32(_counter[7] < cOld[7]);

            /* Calculate the g-functions */
            for (var i = 0; i < 8; i++) g[i] = GFunc(_state[i] + _counter[i]);

            /* Calculate new state values */
            _state[0] = g[0] + RotLeft(g[7], 16) + RotLeft(g[6], 16);
            _state[1] = g[1] + RotLeft(g[0], 8) + g[7];
            _state[2] = g[2] + RotLeft(g[1], 16) + RotLeft(g[0], 16);
            _state[3] = g[3] + RotLeft(g[2], 8) + g[1];
            _state[4] = g[4] + RotLeft(g[3], 16) + RotLeft(g[2], 16);
            _state[5] = g[5] + RotLeft(g[4], 8) + g[3];
            _state[6] = g[6] + RotLeft(g[5], 16) + RotLeft(g[4], 16);
            _state[7] = g[7] + RotLeft(g[6], 8) + g[5];
        }

        /// <summary>
        /// Square a 32-bit unsigned integer to obtain the 64-bit result 
        /// and return the upper 32 bits XOR the lower 32 bits.
        /// </summary>
        private static uint GFunc (uint state) {
            // Construct high and low argument for squaring
            uint a = state & 0xFFFF;
            uint b = state >> 16;
            // Calculate high and low result of squaring
            uint h = ((((a * a) >> 17) + (a * b)) >> 15) + b * b;
            uint l = state * state;
            // Return high XOR low
            return h ^ l;
        }
        #endregion
    }
}