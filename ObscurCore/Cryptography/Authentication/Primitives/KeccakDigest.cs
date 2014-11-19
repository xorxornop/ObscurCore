#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using PerfCopy;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
    /// <summary>
    ///     SHA-3/Keccak sponge construction implemented as a digest/hash function.
    /// </summary>
    public partial class KeccakDigest : HashEngine
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

        private readonly int _keccakR;
        private readonly int _stateSizeBytes;
        protected int BuffLength;
        private byte[] _buffer;
        private ulong[] _state = new ulong[5 * 5]; //1600 bits

        public KeccakDigest(int sizeInBits)
            : base((HashFunction)Enum.Parse(typeof(HashFunction), "Keccak" + sizeInBits))
        {
            switch (HashIdentity) {
                case HashFunction.Keccak224:
                    _keccakR = 1152;
                    break;
                case HashFunction.Keccak256:
                    _keccakR = 1088;
                    break;
                case HashFunction.Keccak384:
                    _keccakR = 832;
                    break;
                case HashFunction.Keccak512:
                    _keccakR = 576;
                    break;
                default:
                    throw new ArgumentException("");
            }

            BuffLength = 0;
            _stateSizeBytes = _keccakR / 8;
            _buffer = new byte[_stateSizeBytes];
        }

        /// <inheritdoc />
        public override int StateSize
        {
            get { return _stateSizeBytes; }
        }

        private static ulong ROL(ulong a, int offset)
        {
            return (((a) << ((offset) % KeccakLaneSizeInBits)) ^
                    ((a) >> (KeccakLaneSizeInBits - ((offset) % KeccakLaneSizeInBits))));
        }

        private void AddToBuffer(byte[] array, ref int offset, ref int count)
        {
            int amount = Math.Min(count, _buffer.Length - BuffLength);
            array.DeepCopy_NoChecks(offset, _buffer, BuffLength, amount);
            offset += amount;
            BuffLength += amount;
            count -= amount;
        }

        // Added interface members

        /// <inheritdoc />
        protected internal override void BlockUpdateInternal(byte[] input, int inOff, int length)
        {
            HashCore(input, inOff, length);
        }

        /// <inheritdoc />
        protected internal override int DoFinalInternal(byte[] output, int outOff)
        {
            HashFinal(output, outOff);
            Reset();
            return OutputSize;
        }
    }
}
