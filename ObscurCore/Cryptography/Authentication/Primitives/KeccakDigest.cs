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

// Modified from https://bitbucket.org/jdluzen/sha3. Released under Modified BSD License.

using System;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
    /// <summary>
    /// SHA-3/Keccak sponge construction implemented as a digest/hash function.
    /// </summary>
    public partial class KeccakDigest : IDigest
    {
        private const int KeccakB = 1600;
        private const int KeccakNumberOfRounds = 24;
        private const int KeccakLaneSizeInBits = 8 * 8;

        private static readonly ulong[] RoundConstants = {
            0x0000000000000001UL,
            0x0000000000008082UL,
            0x800000000000808aUL,
            0x8000000080008000UL,
            0x000000000000808bUL,
            0x0000000080000001UL,
            0x8000000080008081UL,
            0x8000000000008009UL,
            0x000000000000008aUL,
            0x0000000000000088UL,
            0x0000000080008009UL,
            0x000000008000000aUL,
            0x000000008000808bUL,
            0x800000000000008bUL,
            0x8000000000008089UL,
            0x8000000000008003UL,
            0x8000000000008002UL,
            0x8000000000000080UL,
            0x000000000000800aUL,
            0x800000008000000aUL,
            0x8000000080008081UL,
            0x8000000000008080UL,
            0x0000000080000001UL,
            0x8000000080008008UL
        };

        private ulong[] _state = new ulong[5 * 5]; //1600 bits
        private byte[] _buffer;
        protected int BuffLength;

        private readonly int _hashSizeValue;

        private readonly int _keccakR;

        public KeccakDigest(int size, bool bits)
        {
            if (!bits) {
                size *= 8;
            }

            switch (size) {
                case 224:
                    _keccakR = 1152;
                    break;
                case 256:
                    _keccakR = 1088;
                    break;
                case 384:
                    _keccakR = 832;
                    break;
                case 512:
                    _keccakR = 576;
                    break;
                default:
                    throw new ArgumentException("Output size must be 224, 256, 384, or 512 bits", "size");
            }

            BuffLength = 0;
            _hashSizeValue = size;
            _buffer = new byte[_keccakR / 8];
        }

        private static ulong ROL(ulong a, int offset)
        {
            return (((a) << ((offset) % KeccakLaneSizeInBits)) ^
                    ((a) >> (KeccakLaneSizeInBits - ((offset) % KeccakLaneSizeInBits))));
        }

        private void AddToBuffer(byte[] array, ref int offset, ref int count)
        {
            var amount = Math.Min(count, _buffer.Length - BuffLength);
            array.CopyBytes(offset, _buffer, BuffLength, amount);
            offset += amount;
            BuffLength += amount;
            count -= amount;
        }

        // Added interface members

        /// <inheritdoc />
        public string AlgorithmName
        {
            get { return "Keccak" + _hashSizeValue; }
        }

        /// <inheritdoc />
        public int ByteLength
        {
            get { return _keccakR / 8; }
        }

        /// <inheritdoc />
        public int DigestSize
        {
            get { return _hashSizeValue / 8; }
        }

        /// <inheritdoc />
        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            if (inOff < 0) {
                throw new ArgumentOutOfRangeException("inOff", "Offset out of range.");
            }
            HashCore(input, inOff, length);
        }

        /// <inheritdoc />
        public int DoFinal(byte[] output, int outOff)
        {
            if (outOff < 0) {
                throw new ArgumentOutOfRangeException("outOff", "Offset out of range.");
            }

            HashFinal(output, outOff);
            Reset();
            return DigestSize;
        }
    }
}
