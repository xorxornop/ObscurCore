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
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
    public sealed class RabbitEngine : IStreamCipher
    {
        // Stores engine state
        private byte[]          _workingKey     = null,
                                _workingIV      = null;

        private bool	        _initialised    = false;
        private readonly uint[] state              = new uint[8],
                                counter              = new uint[8];
        private uint counterarry;

        private readonly uint[] constants = new uint[] { 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
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

        public void Reset () {
            KeySetup(_workingKey);
            IVSetup(_workingIV);
            _initialised = true;
        }

        public byte ReturnByte (byte input) {
            //if (limitExceeded()) {
            //throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
            //}
            if (!_initialised) throw new InvalidOperationException(AlgorithmName + " not initialised.");

            throw new NotImplementedException(); // TODO: yes... I need to buffer input, and I haven't gotten round to it yet.
            //return 0;
        }

        public void ProcessBytes (byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff) {
            if (!_initialised) {
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
            }

            if ((inOff + len) > inBytes.Length) {
				throw new ArgumentException("Input buffer too short.");
            }

            if ((outOff + len) > outBytes.Length) {
				throw new ArgumentException("Output buffer too short.");
            }

            //if (limitExceeded(len)) {
            //throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
            //}
            
            XORKeystream(inBytes, inOff, len, outBytes, outOff);
        }

        #region Private implementation
        /// <summary>
        /// XORs generates keystream with input data.
        /// </summary>
        /// <param name="inBytes">Input byte array must be a multiple of 16 in length.</param>
        /// <returns></returns>
        private void XORKeystream (byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff) {
            int truncatedLen;
            var blocks = Math.DivRem(len, 16, out truncatedLen);
            for (var i = 0; i < blocks; i++) {
                NextState();
                Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff) ^ state[0] ^ (state[5] >> 16) ^ (state[3] << 16), outBytes, outOff);
                Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 4) ^ state[2] ^ (state[7] >> 16) ^ (state[5] << 16), outBytes, outOff + 4);
                Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 8) ^ state[4] ^ (state[1] >> 16) ^ (state[7] << 16), outBytes, outOff + 8);
                Pack.UInt32_To_LE(Pack.LE_To_UInt32(inBytes, inOff + 12) ^ state[6] ^ (state[3] >> 16) ^ (state[1] << 16), outBytes, outOff + 12);
                inOff += 16;
                outOff += 16;
            }
            if (truncatedLen == 0) return;

            var inTruncated = new byte[16];
            var outTruncated = new byte[16];
            Array.Copy(inBytes, inOff, inTruncated, 0, truncatedLen);
            NextState();
            Pack.UInt32_To_LE(Pack.LE_To_UInt32(inTruncated, 0) ^ state[0] ^ (state[5] >> 16) ^ (state[3] << 16), outTruncated, 0);
            Pack.UInt32_To_LE(Pack.LE_To_UInt32(inTruncated, 4) ^ state[2] ^ (state[7] >> 16) ^ (state[5] << 16), outTruncated, 4);
            Pack.UInt32_To_LE(Pack.LE_To_UInt32(inTruncated, 8) ^ state[4] ^ (state[1] >> 16) ^ (state[7] << 16), outTruncated, 8);
            Pack.UInt32_To_LE(Pack.LE_To_UInt32(inTruncated, 12) ^ state[6] ^ (state[3] >> 16) ^ (state[1] << 16), outTruncated, 12);
            Array.Copy(outTruncated, 0, outBytes, outOff, truncatedLen);
        }

        /// <summary>
        /// Get raw keystream in a multiple of 16 bytes length.
        /// </summary>
        private byte[] GenerateKeystream(int blocks) {
            var outBytes = new byte[16 * blocks];
            var outOffset = 0;
            for (var i = 0; i < blocks; i++)
            {
                NextState();
                Pack.UInt32_To_LE(state[0] ^ (state[5] >> 16) ^ (state[3] << 16), outBytes, outOffset);
                Pack.UInt32_To_LE(state[2] ^ (state[7] >> 16) ^ (state[5] << 16), outBytes, outOffset + 4);
                Pack.UInt32_To_LE(state[4] ^ (state[1] >> 16) ^ (state[7] << 16), outBytes, outOffset + 8);
                Pack.UInt32_To_LE(state[6] ^ (state[3] >> 16) ^ (state[1] << 16), outBytes, outOffset + 12);
                outOffset += 16;
            }
            return outBytes;
        }

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
            state[0] = k[0];
            state[2] = k[1];
            state[4] = k[2];
            state[6] = k[3];
            state[1] = (k[3] << 16) | (k[2] >> 16);
            state[3] = (k[0] << 16) | (k[3] >> 16);
            state[5] = (k[1] << 16) | (k[0] >> 16);
            state[7] = (k[2] << 16) | (k[1] >> 16);

            // Generate initial counter values
            counter[0] = RotLeft(k[2], 16);
            counter[2] = RotLeft(k[3], 16);
            counter[4] = RotLeft(k[0], 16);
            counter[6] = RotLeft(k[1], 16);
            counter[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF);
            counter[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF);
            counter[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF);
            counter[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF);

            // Clear carry bit
            counterarry = 0;

            // Iterate the system four times
            for (var j = 0; j < 4; j++) NextState();

            // Iterate the counters
            for (var j = 0; j < 8; j++) counter[j] ^= state[(j + 4) & 0x7];
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
                counter[index] ^= i[subIndex];
                if (++subIndex > 3) subIndex = 0;
            }

            // Iterate the system four times
            for (var j = 0; j < 4; j++) NextState();
        }

        private static uint RotLeft (uint state, int rot) {
            return (state << rot) | (state >> (32 - rot));
        }

        private void NextState () {
            // Temporary variables
            uint[] g = new uint[8], cOld = new uint[8];

            /* Save old counter values */
            for (var i = 0; i < 8; i++) cOld[i] = counter[i];

            /* Calculate new counter values */
            counter[0] += constants[0] + counterarry;
            for (var i = 1; i < 8; i++) {
                counter[i] += constants[i] + Convert.ToUInt32(counter[i - 1] < cOld[i - 1]);
            }
            counterarry = Convert.ToUInt32(counter[7] < cOld[7]);

            /* Calculate the g-functions */
            for (var i = 0; i < 8; i++) g[i] = GFunc(state[i] + counter[i]);

            /* Calculate new state values */
            state[0] = g[0] + RotLeft(g[7], 16) + RotLeft(g[6], 16);
            state[1] = g[1] + RotLeft(g[0], 8) + g[7];
            state[2] = g[2] + RotLeft(g[1], 16) + RotLeft(g[0], 16);
            state[3] = g[3] + RotLeft(g[2], 8) + g[1];
            state[4] = g[4] + RotLeft(g[3], 16) + RotLeft(g[2], 16);
            state[5] = g[5] + RotLeft(g[4], 8) + g[3];
            state[6] = g[6] + RotLeft(g[5], 16) + RotLeft(g[4], 16);
            state[7] = g[7] + RotLeft(g[6], 8) + g[5];
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