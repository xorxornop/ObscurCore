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

namespace ObscurCore.Cryptography.Authentication.Primitives
{
    public sealed class Blake2BMac : Blake2BDigest, IMac
    {
        /// <summary>
        ///     If MAC function has been initialised.
        /// </summary>
        private bool _isInitialised;

        /// <summary>
        ///     Initializes a new instance of the <see cref="Blake2BMac" /> class.
        /// </summary>
        /// <param name="sizeInBits">Size of the MAC to produce.</param>
        public Blake2BMac(int sizeInBits)
            : base(sizeInBits, false) {}

        #region IMac Members

        /// <summary>
        ///     Enumerated identity of the MAC function.
        /// </summary>
        public new MacFunction Identity 
        {
            get { return (MacFunction)Enum.Parse(typeof(MacFunction), base.Identity.ToString()); } 
        }

        public void Init(byte[] key)
        {
            this.Init(key, null, null);
        }

        #endregion

        /// <summary>
        ///     Initialise the MAC primitive with a key and/or salt and/or a tag.
        /// </summary>
        /// <param name="key">Key for the MAC. Maximum 64 bytes.</param>
        /// <param name="salt">Salt for the MAC. Maximum 16 bytes.</param>
        /// <param name="tag">Tag/personalisation to include in the IV for the MAC. Maximum 16 bytes.</param>
        public void Init(byte[] key, byte[] salt, byte[] tag)
        {
            byte[] keyBytes = null, saltBytes = null, tagBytes = null;

            if (key != null) {
                if (key.Length > 64) {
                    throw new ArgumentOutOfRangeException("key", "Key is longer than 64 bytes.");
                }
                keyBytes = new byte[key.Length];
                Array.Copy(key, keyBytes, key.Length);
            }

            if (salt != null) {
                if (salt.Length > 16) {
                    throw new ArgumentOutOfRangeException("salt", "Salt is longer than 16 bytes.");
                }
                saltBytes = new byte[16];
                Array.Copy(salt, saltBytes, salt.Length);
            }

            if (tag != null) {
                if (tag.Length > 16) {
                    throw new ArgumentOutOfRangeException("tag", "Tag is longer than 16 bytes.");
                }
                tagBytes = new byte[16];
                Array.Copy(tag, tagBytes, tag.Length);
            }

            var config = new Blake2BCore.Blake2BConfig {
                Key = keyBytes,
                Salt = saltBytes,
                Personalization = tagBytes,
                OutputSizeInBytes = base.OutputSize,
            };

            _isInitialised = true;
            base.InitCore(config);
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
            if (_isInitialised == false) {
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
            if (_isInitialised == false) {
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
    }
}
