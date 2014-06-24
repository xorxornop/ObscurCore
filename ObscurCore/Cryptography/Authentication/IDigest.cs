//
//  Copyright 2014  Matthew Ducker
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

namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    ///     Interface that a digest/hash function conforms to.
    /// </summary>
    public interface IDigest
    {
        /// <summary>
        ///     The name of the algorithm that the digest implements.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        ///     Size of output in bytes that the digest emits upon finalisation.
        /// </summary>
        int DigestSize { get; }

        /// <summary>
        ///     Size in bytes of internal buffer.
        /// </summary>
        int ByteLength { get; }

        /// <summary>
        ///     Update the internal state of the digest with a single byte.
        /// </summary>
        /// <param name="input">Byte to input.</param>
        void Update(byte input);

        /// <summary>
        ///     Update the internal state of the digest with a chunk of bytes.
        /// </summary>
        /// <param name="input">The array containing the input.</param>
        /// <param name="inOff">The offset in <paramref name="input"/> that the input begins at.</param>
        /// <param name="len">The length of the input starting at <paramref name="inOff"/>.</param>
        void BlockUpdate(byte[] input, int inOff, int len);

        /// <summary>
        ///     Compute and output the final state, and reset the internal state of the digest.
        /// </summary>
        /// <param name="output">Array that the digest value is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output"/> that the output is to start at.
        /// </param>
        /// <returns>Size of the output in bytes.</returns>
        int DoFinal(byte[] output, int outOff);

        /// <summary>
        /// Reset the digest back to it's initial state.
        /// </summary>
        void Reset();
    }
}
