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

namespace Obscur.Core.Cryptography.Authentication.Primitives
{
    /// <summary>
    ///     Keccak (SHA3) algorithm implemented as a Message Authentication Code (MAC). Variable output size.
    /// </summary>
    public class KeccakMac : KeccakDigest, IMac
    {
        private byte[] _key;
        /// <summary>
        ///     If MAC function has been initialised.
        /// </summary>
        protected bool IsInitialised;

        /// <summary>
        ///     Initializes a new instance of the <see cref="KeccakMac" /> class.
        /// </summary>
        /// <param name="sizeInBits">Size of the MAC produced in bits. Supported sizes are 224, 256, 384, and 512.</param>
        public KeccakMac(int sizeInBits)
            : base(sizeInBits) {}

        #region IMac Members

        /// <summary>
        ///     Enumerated function identity.
        /// </summary>
        public new MacFunction Identity
        {
            get { return (MacFunction) Enum.Parse(typeof (MacFunction), base.Identity.ToString()); }
        }

        /// <summary>
        ///     Set the initial state of the MAC function. Required before other use.
        /// </summary>
        /// <param name="key"></param>
        public void Init(byte[] key)
        {
            _key = key;
            IsInitialised = true;
            if (key.IsNullOrZeroLength() == false) {
                BlockUpdate(key, 0, key.Length);
            } 
        }

        /// <summary>
        ///     Update the internal state of the MAC function with a chunk of bytes.
        /// </summary>
        /// <param name="input">The array containing the input.</param>
        /// <param name="inOff">The offset in <paramref name="input" /> that the input begins at.</param>
        /// <param name="length">The length of the input starting at <paramref name="inOff" />.</param>
        /// <exception cref="InvalidOperationException">The MAC function is not initialised.</exception>
        /// <exception cref="ArgumentOutOfRangeException">An input parameter is out of range (e.g. offset or length is under 0).</exception>
        /// <exception cref="DataLengthException">
        ///     A input or output buffer is of insufficient length.
        /// </exception>
        public override void BlockUpdate(byte[] input, int inOff, int length)
        {
            if (IsInitialised == false) {
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
            }
            if (input == null) {
                throw new ArgumentNullException("input");
            }
            if (inOff < 0) {
                throw new ArgumentOutOfRangeException("inOff");
            }
            if (length < 0) {
                throw new ArgumentOutOfRangeException("length");
            }
            if ((inOff + length) > input.Length) {
                throw new DataLengthException("Input buffer too short.");
            }
            if (length < 1) {
                return;
            }

            BlockUpdateInternal(input, inOff, length);
        }

        /// <summary>
        ///     Compute and output the final state, and reset the internal state of the MAC function.
        /// </summary>
        /// <param name="output">Array that the MAC is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output" /> that the output is to start at.
        /// </param>
        /// <exception cref="InvalidOperationException">The MAC function is not initialised.</exception>
        /// <exception cref="ArgumentOutOfRangeException">An input parameter is out of range (e.g. offset is under 0).</exception>
        /// <exception cref="DataLengthException">
        ///     A input or output buffer is of insufficient length.
        /// </exception>
        /// <returns>Size of the output in bytes.</returns>
        public override int DoFinal(byte[] output, int outOff)
        {
            if (IsInitialised == false) {
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
            }
            if (output == null) {
                throw new ArgumentNullException("output");
            }
            if (outOff < 0) {
                throw new ArgumentOutOfRangeException("outOff");
            }
            if ((outOff + OutputSize) > output.Length) {
                throw new DataLengthException("Output buffer too short.");
            }

            return DoFinalInternal(output, outOff);
        }

        /// <summary>
        ///     Reset the MAC to the same state as it was after the last init (if there was one).
        /// </summary>
        public override void Reset()
        {
            base.Reset();
            Init(_key);
        }

        #endregion
    }
}
