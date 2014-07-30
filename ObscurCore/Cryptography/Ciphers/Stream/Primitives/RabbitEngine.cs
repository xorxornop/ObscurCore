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
	public sealed class RabbitEngine : StreamCipherEngine, ICsprngCompatible
    {
		private static uint[] A = new uint[] { 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 
                                               0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3 };

		private static uint rotl(uint value, int shift) {
			return value << shift | value >> 32 - shift;
		}

		private uint[] X = new uint[8];
		private uint[] C = new uint[8];
	    private byte b;

		private byte[] _keyStream 		= new byte[16];
		private int _keyStreamPtr 	= 16;

        public RabbitEngine()
            : base(StreamCipher.Rabbit)
	    {
	    }

	    protected override void InitState()
	    {
	        Reset();
	    }

	    public override string AlgorithmName {
            get { return "Rabbit"; }
        }

		public override int StateSize
		{
			get { return 16; }
		}

        public override void Reset () {
            KeySetup(Key);
            IVSetup(Nonce);
            IsInitialised = true;
			_keyStream.SecureWipe();
			_keyStreamPtr = 16;
        }

        public override byte ReturnByte (byte input) {
            if (!IsInitialised) throw new InvalidOperationException(AlgorithmName + " not initialised.");

			if (_keyStreamPtr == 16) {
				GenerateKeystream (_keyStream, 0);
				_keyStreamPtr = 0;
			}
			return (byte)(_keyStream [_keyStreamPtr++] ^ input);
        }

	    internal override void ProcessBytesInternal (byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff) {
			if (_keyStreamPtr < 16) {
				var blockLength = 16 - _keyStreamPtr;
				if (blockLength > len) {
					blockLength = len;
				}
				
                inBytes.XorInternal(inOff, _keyStream, _keyStreamPtr, outBytes, outOff, blockLength);
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
            unsafe {
                fixed (byte* inPtr = inBytes) {
                    fixed (byte* outPtr = outBytes) {
                        uint* inUintPtr = (uint*)(inPtr + inOff);
                        uint* outUintPtr = (uint*)(outPtr + outOff);
                        for (var i = 0; i < blocks; i++) {
                            NextState();
                            outUintPtr[0] = inUintPtr[0] ^ (X[6] ^ (X[3] >> 16) ^ (X[1] << 16));
                            outUintPtr[1] = inUintPtr[1] ^ (X[4] ^ (X[1] >> 16) ^ (X[7] << 16));
                            outUintPtr[2] = inUintPtr[2] ^ (X[2] ^ (X[7] >> 16) ^ (X[5] << 16));
                            outUintPtr[3] = inUintPtr[3] ^ (X[0] ^ (X[5] >> 16) ^ (X[3] << 16));
                            inUintPtr += 4;
                            outUintPtr += 4;
                        }
                    }
                }
            }
            inOff += 16 * blocks;
            outOff += 16 * blocks;
			#else
			for (var i = 0; i < blocks; i++) {
				NextState();
				UInt32 x = Pack.LE_To_UInt32(inBytes, inOff + 0) ^ X[6] ^ X[3] >> 16 ^ X[1] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 0);
				x = Pack.LE_To_UInt32(inBytes, inOff + 4) ^ X[4] ^ X[1] >> 16 ^ X[7] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 4);
				x = Pack.LE_To_UInt32(inBytes, inOff + 8) ^ X[2] ^ X[7] >> 16 ^ X[5] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 8);
				x = Pack.LE_To_UInt32(inBytes, inOff + 12) ^ X[0] ^ X[5] >> 16 ^ X[3] << 16;
				Pack.UInt32_To_LE(x, outBytes, outOff + 12);
				inOff += 16;
				outOff += 16;
			}
			#endif

            if (remainder > 0) {
                GenerateKeystream (_keyStream, 0);
                inBytes.XorInternal(inOff, _keyStream, 0, outBytes, outOff, remainder);
			    _keyStreamPtr = remainder;
            }
        }

		public void GetKeystream(byte[] buffer, int offset, int length) {
			if (_keyStreamPtr < 16) {
				var blockLength = 16 - _keyStreamPtr;
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
			if (length > 0) {
				GenerateKeystream (_keyStream, 0);
				Array.Copy(_keyStream, 0, buffer, offset, length);
				_keyStreamPtr = length;
			}
		}

		private void GenerateKeystream(byte[] buffer, int offset) {
			NextState();
			UInt32 x = X[6] ^ X[3] >> 16 ^ X[1] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 0);
			x = X[4] ^ X[1] >> 16 ^ X[7] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 4);
			x = X[2] ^ X[7] >> 16 ^ X[5] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 8);
			x = X[0] ^ X[5] >> 16 ^ X[3] << 16;
			Pack.UInt32_To_LE(x, buffer, offset + 12);
		}

        #region Private implementation

        /// <summary>
        /// Initialise the engine state with key material.
        /// </summary>
        private void KeySetup (byte[] key) {
			var sKey = new UInt16[key.Length >> 1];
			for (var i = 0; i < sKey.Length; ++i) {
                sKey[i] = (UInt16)((key[i << 1] << 8) | key[(2 << 1) + 1]);
			}
			setupKey(sKey);
        }

        public void setupKey(UInt16[] key)
        {
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

            var sIV = new UInt16[iv.Length >> 1];
			for (var i = 0; i < sIV.Length; i++) {
                sIV[i] = (UInt16)((iv[i << 1] << 8) | iv[(2 << 1) + 1]);
			}
			setupIVPost (sIV);
        }

        private void setupIVPost(UInt16[] iv)
        {
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
			for (var j = 0; j < 8; ++j) {
                UInt64 t = (C[j] & 0xFFFFFFFFul) + (A[j] & 0xFFFFFFFFul) + b;
				b = (byte) (t >> 32);
				C[j] = (uint) (t & 0xFFFFFFFF);
			}
			/*			 next state function */
			var G = new UInt32[8];
			for (var j = 0; j < 8; ++j) {
				// TODO: reduce this to use 32 bits only
				UInt64 t = X[j] + C[j] & 0xFFFFFFFFul;
                G[j] = (UInt32)((t *= t) ^ t >> 32);
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