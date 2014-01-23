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

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
	public sealed class RabbitEngine : IStreamCipher, ICsprngCompatible
    {
		private const int KEYSTREAM_LENGTH = 16;

		private static uint[] A = new uint[] { 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
			0xD34D34D3 };

        // Stores engine state
        private byte[]          _workingKey,
                                _workingIV;

        private bool	        _initialised;

		private static uint rotl(uint value, int shift) {
			return value << shift | value >> 32 - shift;
		}

		private uint[] X = new uint[8];
		private uint[] C = new uint[8];
		private byte b = 0;



		private byte[] 			_keyStream 		= new byte[16];
		private int 			_keyStreamPtr 	= 16;

		private readonly uint[] constants = new uint[] 	{ 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
                                                          0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3 };


		public void Init (bool encrypting, byte[] key, byte[] iv) {
			if (iv == null) 
				throw new ArgumentNullException("iv", "Rabbit initialisation requires an IV.");
			if (iv.Length != 8)
				throw new ArgumentException("Rabbit requires exactly 8 bytes of IV.", "iv");

			_workingIV = iv;

			if (key == null) 
				throw new ArgumentNullException("key", "Rabbit initialisation requires a key.");
			if (key.Length != 16)
				throw new ArgumentException("Rabbit requires an exactly 16 byte key.", "key");

			_workingKey = key;

			Reset ();
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
				GenerateKeystream (_keyStream, 0);
				_keyStreamPtr = 0;
			}
			return (byte)(_keyStream [_keyStreamPtr++] ^ input);
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
					outBytes [outOff + i] = (byte)(_keyStream [_keyStreamPtr + i] ^ inBytes [inOff + i]);
				}
				_keyStreamPtr += blockLength;
				inOff += blockLength;
				outOff += blockLength;
				len -= blockLength;
			}

			if (len == 0)
				return;

			int remainder;
			var blocks = Math.DivRem(len, 16, out remainder);

			#if INCLUDE_UNSAFE
			if(BitConverter.IsLittleEndian) {
				unsafe {
					fixed (byte* inPtr = inBytes) {
						fixed (byte* outPtr = outBytes) {
							uint* inLongPtr = (uint*)(inPtr + inOff);
							uint* outLongPtr = (uint*)(outPtr + outOff);
							for (int i = 0; i < blocks; i++) {
								NextState();
								outLongPtr[0] = inLongPtr[0] ^ X[6] ^ (X[3] >> 16) ^ (X[1] << 16);
								outLongPtr[1] = inLongPtr[1] ^ X[4] ^ (X[1] >> 16) ^ (X[7] << 16);
								outLongPtr[2] = inLongPtr[2] ^ X[2] ^ (X[7] >> 16) ^ (X[5] << 16);
								outLongPtr[3] = inLongPtr[3] ^ X[0] ^ (X[5] >> 16) ^ (X[3] << 16);
								inLongPtr += 4;
								outLongPtr += 4;
							}
						}
					}
				}
				inOff += 16 * blocks;
				outOff += 16 * blocks;
			} else {
				for (int i = 0; i < blocks; i++) {
					NextState();
					Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 0) ^ X[6] ^ (X[3] >> 16) ^ (X[1] << 16), outBytes, outOff + 0);
					Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 4) ^ X[4] ^ (X[1] >> 16) ^ (X[7] << 16), outBytes, outOff + 4);
					Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 8) ^ X[2] ^ (X[7] >> 16) ^ (X[5] << 16), outBytes, outOff + 8);
					Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 12) ^ X[0] ^ (X[5] >> 16) ^ (X[3] << 16), outBytes, outOff + 12);
					inOff += 16;
					outOff += 16;
				}
			}
			#else
			for (int i = 0; i < blocks; i++) {
				NextState();
				uint x = Pack.LE_To_UInt32(inBytes, inOff + 0) ^ X[6] ^ X[3] >> 16 ^ X[1] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 0);
//				outBytes[outOff + 0] = (byte)((x >> 24) ^ inBytes[inOff + 0]);
//				outBytes[outOff + 1] = (byte)((x >> 16) ^ inBytes[inOff + 1]);
//				outBytes[outOff + 2] = (byte)((x >> 8) ^ inBytes[inOff + 2]);
//				outBytes[outOff + 3] = (byte)(x ^ inBytes[inOff + 3]);
				x = Pack.LE_To_UInt32(inBytes, inOff + 4) ^ X[4] ^ X[1] >> 16 ^ X[7] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 4);
//				outBytes[outOff + 4] = (byte)((x >> 24) ^ inBytes[inOff + 4]);
//				outBytes[outOff + 5] = (byte)((x >> 16) ^ inBytes[inOff + 5]);
//				outBytes[outOff + 6] = (byte)((x >> 8) ^ inBytes[inOff + 6]);
//				outBytes[outOff + 7] = (byte)(x ^ inBytes[inOff + 7]);
				x = Pack.LE_To_UInt32(inBytes, inOff + 8) ^ X[2] ^ X[7] >> 16 ^ X[5] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 8);
//				outBytes[outOff + 8] = (byte)((x >> 24) ^ inBytes[inOff + 8]);
//				outBytes[outOff + 9]= (byte)((x >> 16) ^ inBytes[inOff + 9]);
//				outBytes[outOff + 10] = (byte)((x >> 8) ^ inBytes[inOff + 10]);
//				outBytes[outOff + 11] = (byte)(x ^ inBytes[inOff + 11]);
				x = Pack.LE_To_UInt32(inBytes, inOff + 12) ^ X[0] ^ X[5] >> 16 ^ X[3] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 12);
//				outBytes[outOff + 12] = (byte)((x >> 24) ^ inBytes[inOff + 12]);
//				outBytes[outOff + 13] = (byte)((x >> 16) ^ inBytes[inOff + 13]);
//				outBytes[outOff + 14] = (byte)((x >> 8) ^ inBytes[inOff + 14]);
//				outBytes[outOff + 15] = (byte)(x ^ inBytes[inOff + 15]);
				inOff += 16;
				outOff += 16;
			}
			#endif

			if (remainder == 0) return;

			GenerateKeystream (_keyStream, 0);
			for (int i = 0; i < remainder; i++) {
				outBytes[outOff + i] = (byte) (inBytes[inOff + i] ^ _keyStream[i]);
			}
			_keyStreamPtr = remainder;
        }

		public void GetKeystream(byte[] buffer, int offset, int length) {
			if (_keyStreamPtr < 16) {
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
				GenerateKeystream (buffer, offset);
				offset += 16;
				length -= 16;
			}
			if(length > 0) {
				GenerateKeystream (_keyStream, 0);
				Array.Copy(_keyStream, 0, buffer, offset, length);
				_keyStreamPtr = length;
			}
		}

		private void GenerateKeystream(byte[] buffer, int offset) {
			NextState();
			uint x = X[6] ^ X[3] >> 16 ^ X[1] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 0);
//			buffer[offset + 0] = (byte) (x >> 24);
//			buffer[offset + 1] = (byte) (x >> 16);
//			buffer[offset + 2] = (byte) (x >> 8);
//			buffer[offset + 3] = (byte) x;
			x = X[4] ^ X[1] >> 16 ^ X[7] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 4);
//			buffer[offset + 4] = (byte) (x >> 24);
//			buffer[offset + 5] = (byte) (x >> 16);
//			buffer[offset + 6] = (byte) (x >> 8);
//			buffer[offset + 7] = (byte) x;
			x = X[2] ^ X[7] >> 16 ^ X[5] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 8);
//			buffer[offset + 8] = (byte) (x >> 24);
//			buffer[offset + 9] = (byte) (x >> 16);
//			buffer[offset + 10] = (byte) (x >> 8);
//			buffer[offset + 11] = (byte) x;
			x = X[0] ^ X[5] >> 16 ^ X[3] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 12);
//			buffer[offset + 12] = (byte) (x >> 24);
//			buffer[offset + 13] = (byte) (x >> 16);
//			buffer[offset + 14] = (byte) (x >> 8);
//			buffer[offset + 15] = (byte) x;
		}

        #region Private implementation

        /// <summary>
        /// Initialise the engine state with key material.
        /// </summary>
        private void KeySetup (byte[] key) {
			ushort[] sKey = new ushort[key.Length>>1];
			for (int i = 0; i < sKey.Length; ++i) {
				sKey [i] = (ushort)((key [i << 1] << 8) | key [(2 << 1) + 1]);
			}
			setupKey(sKey);
        }

		public void setupKey(ushort[] key) {
			/*			 unroll */
			X[0] = (uint)key[1] << 16 | (uint)(key[0] & 0xFFFF);
			X[1] = (uint)key[6] << 16 | (uint)(key[5] & 0xFFFF);
			X[2] = (uint)key[3] << 16 | (uint)(key[2] & 0xFFFF);
			X[3] = (uint)key[0] << 16 | (uint)(key[7] & 0xFFFF);
			X[4] = (uint)key[5] << 16 | (uint)(key[4] & 0xFFFF);
			X[5] = (uint)key[2] << 16 | (uint)(key[1] & 0xFFFF);
			X[6] = (uint)key[7] << 16 | (uint)(key[6] & 0xFFFF);
			X[7] = (uint)key[4] << 16 | (uint)(key[3] & 0xFFFF);
			/*			 unroll */
			C[0] = (uint)key[4] << 16 | (uint)(key[5] & 0xFFFF);
			C[1] = (uint)key[1] << 16 | (uint)(key[2] & 0xFFFF);
			C[2] = (uint)key[6] << 16 | (uint)(key[7] & 0xFFFF);
			C[3] = (uint)key[3] << 16 | (uint)(key[4] & 0xFFFF);
			C[4] = (uint)key[0] << 16 | (uint)(key[1] & 0xFFFF);
			C[5] = (uint)key[5] << 16 | (uint)(key[6] & 0xFFFF);
			C[6] = (uint)key[2] << 16 | (uint)(key[3] & 0xFFFF);
			C[7] = (uint)key[7] << 16 | (uint)(key[0] & 0xFFFF);
			NextState();
			NextState();
			NextState();
			NextState();
			/*			 unroll */
			C[0] ^= X[4];
			C[1] ^= X[5];
			C[2] ^= X[6];
			C[3] ^= X[7];
			C[4] ^= X[0];
			C[5] ^= X[1];
			C[6] ^= X[2];
			C[7] ^= X[3];
		}

        /// <summary>
        /// Initialise the engine state with initialisation vector material.
        /// </summary>
        private void IVSetup (byte[] iv) {
            if (iv.Length != 8) 
				throw new ArgumentException("IV must be 8 bytes in length.");

			ushort[] sIV = new ushort[iv.Length >> 1];
			for(int i = 0; i < sIV.Length; i++) {
				sIV[i] = (ushort)((iv[i << 1] << 8) | iv[(2 << 1) + 1]);
			}
			setupIVPost (sIV);
        }

		private void setupIVPost(ushort[] iv) {
			/*			 unroll */
			C[0] ^= (uint)iv[1] << 16 | (uint)(iv[0] & 0xFFFF);
			C[1] ^= (uint)iv[3] << 16 | (uint)(iv[1] & 0xFFFF);
			C[2] ^= (uint)iv[3] << 16 | (uint)(iv[2] & 0xFFFF);
			C[3] ^= (uint)iv[2] << 16 | (uint)(iv[0] & 0xFFFF);
			C[4] ^= (uint)iv[1] << 16 | (uint)(iv[0] & 0xFFFF);
			C[5] ^= (uint)iv[3] << 16 | (uint)(iv[1] & 0xFFFF);
			C[6] ^= (uint)iv[3] << 16 | (uint)(iv[2] & 0xFFFF);
			C[7] ^= (uint)iv[2] << 16 | (uint)(iv[0] & 0xFFFF);

			// Iterate the system four times
			NextState();
			NextState();
			NextState();
			NextState();
		}


        private void NextState () {
			/* counter update */
			for(int j = 0; j < 8; ++j) {
				ulong t = (C[j] & 0xFFFFFFFFul) + (A[j] & 0xFFFFFFFFul) + b;
				b = (byte) (t >> 32);
				C[j] = (uint) (t & 0xFFFFFFFF);
			}
			/*			 next state function */
			uint[] G = new uint[8];
			for(int j = 0; j < 8; ++j) {
				// TODO: reduce this to use 32 bits only
				ulong t = X[j] + C[j] & 0xFFFFFFFFul;
				G[j] = (uint) ((t *= t) ^ t >> 32);
			}
			/*			 unroll */
			X[0] = G[0] + rotl(G[7], 16) + rotl(G[6], 16);
			X[1] = G[1] + rotl(G[0], 8) + G[7];
			X[2] = G[2] + rotl(G[1], 16) + rotl(G[0], 16);
			X[3] = G[3] + rotl(G[2], 8) + G[1];
			X[4] = G[4] + rotl(G[3], 16) + rotl(G[2], 16);
			X[5] = G[5] + rotl(G[4], 8) + G[3];
			X[6] = G[6] + rotl(G[5], 16) + rotl(G[4], 16);
			X[7] = G[7] + rotl(G[6], 8) + G[5];
        }
        #endregion
    }
}