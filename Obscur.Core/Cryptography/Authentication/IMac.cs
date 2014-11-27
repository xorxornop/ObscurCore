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

namespace Obscur.Core.Cryptography.Authentication
{
    /// <summary>
    ///     Interface that a Message Authentication Code (MAC) function conforms to.
    /// </summary>
    public interface IMac
    {
        /// <summary>
        ///     Enumerated function identity.
        /// </summary>
        MacFunction Identity { get; }

        /// <summary>
        ///     The name of the algorithm that the MAC function implements.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        ///     Size of output in bytes that the MAC function emits upon finalisation.
        /// </summary>
        int OutputSize { get; }

        /// <summary>
        ///     Set the initial state of the MAC function. Required before other use.
        /// </summary>
        /// <param name="key"></param>
        void Init(byte[] key);

        /// <summary>
        ///     Update the internal state of the MAC function with a single byte.
        /// </summary>
        /// <param name="input">Byte to input.</param>
        /// <exception cref="InvalidOperationException">The MAC function is not initialised.</exception>
        void Update(byte input);

        /// <summary>
        ///     Update the internal state of the MAC function with a chunk of bytes.
        /// </summary>
        /// <param name="input">The array containing the input.</param>
        /// <param name="inOff">The offset in <paramref name="input" /> that the input begins at.</param>
        /// <param name="len">The length of the input starting at <paramref name="inOff" />.</param>
        /// <exception cref="InvalidOperationException">The MAC function is not initialised.</exception>
        void BlockUpdate(byte[] input, int inOff, int len);

        /// <summary>
        ///     Compute and output the final state, and reset the internal state of the MAC.
        /// </summary>
        /// <param name="output">Array that the MAC is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output" /> that the output is to start at.
        /// </param>
        /// <exception cref="InvalidOperationException">The MAC function is not initialised.</exception>
        /// <returns>Size of the output in bytes.</returns>
        int DoFinal(byte[] output, int outOff);

        /// <summary>
        ///     Reset the MAC function back to the same state it was after the last init (if there was one).
        /// </summary>
        void Reset();
    }
}
