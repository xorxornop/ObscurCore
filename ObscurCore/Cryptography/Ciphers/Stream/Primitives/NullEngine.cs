#region License

// 	Copyright 2014-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

#endregion

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
#if DEBUG
    /// <summary>
    ///     "Stream cipher" that does nothing. Strictly used for testing.
    /// </summary>
    public class NullEngine : StreamCipherEngine
    {
        /// <summary>
        ///     Instantiates a new NullEngine instance.
        /// </summary>
        public NullEngine() : base(StreamCipher.None) {}

        /// <summary>
        ///     Merely an arbitrary, convenient length.
        /// </summary>
        public override int StateSize
        {
            get { return 64; }
        }

        /// <summary>
        ///     Initialises this NullEngine for doing nothing.
        /// </summary>
        protected override void InitState() {}

        /// <summary>
        ///     Returns back <paramref name="input" /> byte.
        /// </summary>
        /// <param name="input">Byte to return.</param>
        /// <returns>
        ///     <paramref name="input" />
        /// </returns>
        public override byte ReturnByte(byte input)
        {
            return input;
        }

        /// <summary>
        ///     Does nothing.
        /// </summary>
        public override void Reset() {}

        /// <summary>
        ///     Copies <paramref name="input" /> data into <paramref name="output" /> (e.g. encrypts/decrypts nothing).
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///     The offset in <paramref name="input" /> at which the input data begins.
        /// </param>
        /// <param name="length">The number of bytes to be copied.</param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outOff">
        ///     The offset in <paramref name="output" /> at which to write the output data to.
        /// </param>
        internal override void ProcessBytesInternal(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            input.CopyBytes(inOff, output, outOff, length);
        }
    }
#endif
}
