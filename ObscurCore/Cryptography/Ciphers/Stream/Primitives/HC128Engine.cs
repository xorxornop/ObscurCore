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
using BitManipulator;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
    /// <summary>
    ///     HC-128 stream cipher implementation.
    /// </summary>
    public class Hc128Engine : StreamCipherEngine
    {
        private byte[] _buf = new byte[4];
        private int _idx;
        private uint[] _p = new uint[512];
        private uint[] _q = new uint[512];
        private uint _cnt;

        public Hc128Engine()
            : base(StreamCipher.Hc128)
	    {
	    }

        private static uint F1(uint x)
        {
            return x.RotateRight_NoChecks(7) ^ x.RotateRight_NoChecks(18) ^ (x >> 3);
        }

        private static uint F2(uint x)
        {
            return x.RotateRight_NoChecks(17) ^ x.RotateRight_NoChecks(19) ^ (x >> 10);
        }

        private uint Step()
        {
            uint j = _cnt & 0x1FF;
            uint ret;

            // Precompute resources
            uint dimJ3 = (j - 3) & 0x1FF;
            uint dimJ10 = (j - 10) & 0x1FF;
            uint dimJ511 = (j - 511) & 0x1FF;
            uint dimJ12 = (j - 12) & 0x1FF;

            if (_cnt < 512) {
                _p[j] += (_p[dimJ3].RotateRight_NoChecks(10) ^ _p[dimJ511].RotateRight_NoChecks(23)) + _p[dimJ10].RotateRight_NoChecks(8);
                ret = (_q[_p[dimJ12] & 0xFF] + _q[((_p[dimJ12] >> 16) & 0xFF) + 256]) ^ _p[j];
            } else {
                _q[j] += (_q[dimJ3].RotateLeft_NoChecks(10) ^ _q[dimJ511].RotateLeft_NoChecks(23)) + _q[dimJ10].RotateLeft_NoChecks(8);
                ret = (_p[_q[dimJ12] & 0xFF] + _p[((_q[dimJ12] >> 16) & 0xFF) + 256]) ^ _q[j];
            }
            _cnt = (_cnt + 1) & 0x3FF;
            return ret;
        }

        private void Init()
        {
            _cnt = 0;

            var w = new uint[1280];

            for (int i = 0; i < 16; i++) {
                w[i >> 2] |= ((uint) Key[i] << (8 * (i & 0x3)));
            }
            Array.Copy(w, 0, w, 4, 4);

            for (int i = 0; i < Nonce.Length && i < 16; i++) {
                w[(i >> 2) + 8] |= ((uint) Nonce[i] << (8 * (i & 0x3)));
            }
            Array.Copy(w, 8, w, 12, 4);

            for (uint i = 16; i < 1280; i++) {
                w[i] = F2(w[i - 2]) + w[i - 7] + F1(w[i - 15]) + w[i - 16] + i;
            }

            Buffer.BlockCopy(w, 256 * sizeof (uint), _p, 0, 512 * sizeof (uint));
            Buffer.BlockCopy(w, 768 * sizeof (uint), _q, 0, 512 * sizeof (uint));

            for (int i = 0; i < 512; i++) {
                _p[i] = Step();
            }
            for (int i = 0; i < 512; i++) {
                _q[i] = Step();
            }

            _cnt = 0;
        }

        /// <inheritdoc/>
        public override int StateSize
        {
            get { return 32; }
        }

        /// <inheritdoc />
        protected override void InitState()
        {
            Init();
            IsInitialised = true;
        }

        /// <inheritdoc/>
        private byte GetByte()
        {
            if (_idx == 0) {
                Pack.UInt32_To_LE(Step(), _buf);
            }
            byte ret = _buf[_idx];
            _idx = _idx + 1 & 0x3;
            return ret;
        }

        /// <inheritdoc/>
        protected internal override void ProcessBytesInternal(
            byte[] input,
            int inOff,
            int len,
            byte[] output,
            int outOff)
        {
            // Process leftover keystream
            for (; _idx != 0; _idx = (_idx + 1) & 3) {
                output[outOff++] = (byte) (input[inOff++] ^ _buf[_idx]);
                len--;
            }

            int remainder;
            var blocks = Math.DivRem(len, sizeof(UInt32), out remainder);

#if INCLUDE_UNSAFE
            unsafe {
                fixed (byte* inPtr = input) {
                    fixed (byte* outPtr = output) {
                        var inUintPtr = (UInt32*) (inPtr + inOff);
                        var outUintPtr = (UInt32*) (outPtr + outOff);
                        for (var i = 0; i < blocks; i++) {
                            uint j = _cnt & 0x1FF;
                            uint ret;

                            // Precompute resources
                            uint dimJ3 = (j - 3) & 0x1FF;
                            uint dimJ10 = (j - 10) & 0x1FF;
                            uint dimJ511 = (j - 511) & 0x1FF;
                            uint dimJ12 = (j - 12) & 0x1FF;

                            if (_cnt < 512) {
                                _p[j] += (_p[dimJ3].RotateRight(10) ^ _p[dimJ511].RotateRight(23)) + _p[dimJ10].RotateRight(8);
                                ret = (_q[_p[dimJ12] & 0xFF] + _q[((_p[dimJ12] >> 16) & 0xFF) + 256]) ^ _p[j];
                            } else {
                                _q[j] += (_q[dimJ3].RotateLeft(10) ^ _q[dimJ511].RotateLeft(23)) + _q[dimJ10].RotateLeft(8);
                                ret = (_p[_q[dimJ12] & 0xFF] + _p[((_q[dimJ12] >> 16) & 0xFF) + 256]) ^ _q[j];
                            }
                            _cnt = (_cnt + 1) & 0x3FF;
                            outUintPtr[i] = inUintPtr[i] ^ ret;
                        }
                    }
                }
            }
            inOff += sizeof (uint) * blocks;
            outOff += sizeof (uint) * blocks;
#else
            for (int i = 0; i < blocks; i++) {
				Step().ToLittleEndian(_buf);
				output[outOff + 0] = (byte)(input[inOff + 0] ^ _buf[0]);
				output[outOff + 1] = (byte)(input[inOff + 1] ^ _buf[1]);
				output[outOff + 2] = (byte)(input[inOff + 2] ^ _buf[2]);
				output[outOff + 3] = (byte)(input[inOff + 3] ^ _buf[3]);
				inOff += 4;
				outOff += 4;
			}
#endif

            // Process remainder input (insufficient width for a full step)
            for (var i = 0; i < remainder; i++) {
                if (_idx == 0) {
                    Step().ToLittleEndian(_buf);
                }
                output[outOff++] = (byte) (input[inOff++] ^ _buf[_idx]);
                _idx = (_idx + 1) & 3;
            }
        }

        /// <inheritdoc/>
        public override void Reset()
        {
            _idx = 0;
            Init();
        }

        /// <inheritdoc/>
        public override byte ReturnByte(byte input)
        {
            return (byte) (input ^ GetByte());
        }
    }
}
