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
    ///     Base class for hash function implementations.
    /// </summary>
    public abstract class HashEngine : IHash
    {
        /// <summary>
        ///     Type of hash function, as-per the <see cref="HashFunction" /> enumeration.
        /// </summary>
        protected readonly HashFunction HashIdentity;

        /// <summary>
        ///     Instantiate a new hash function engine.
        /// </summary>
        /// <param name="macIdentity">Identity of the hash function.</param>
        protected HashEngine(HashFunction macIdentity)
        {
            HashIdentity = macIdentity;
        }

        /// <summary>
        ///     Display-friendly name of the hash function.
        /// </summary>
        /// <value>The display name of the hash function.</value>
        public string DisplayName
        {
            get { return Athena.Cryptography.HashFunctions[HashIdentity].DisplayName; }
        }

        #region IHash Members

        /// <summary>
        ///     The name of the hash function algorithm,
        ///     including any configuration-specific identifiers.
        /// </summary>
        public virtual string AlgorithmName
        {
            get { return Identity.ToString(); }
        }

        /// <summary>
        ///     Size of output in bytes that the hash function emits upon finalisation.
        /// </summary>
        public virtual int OutputSize
        {
            get { return Athena.Cryptography.HashFunctions[HashIdentity].OutputSize; }
        }

        /// <summary>
        ///     Enumerated identity of the hash function.
        /// </summary>
        public HashFunction Identity
        {
            get { return HashIdentity; }
        }

        /// <summary>
        ///     The size of operation in bytes the hash function implements internally, e.g. block buffer.
        /// </summary>
        /// <value>The size of the internal operation in bytes.</value>
        public abstract int StateSize { get; }

        /// <summary>
        ///     Update the internal state of the hash function with a single byte.
        /// </summary>
        /// <param name="input">Byte to input.</param>
        public void Update(byte input)
        {
            UpdateInternal(input);
        }

        /// <summary>
        ///     Update the internal state of the hash function with a chunk of bytes.
        /// </summary>
        /// <param name="input">The array containing the input.</param>
        /// <param name="inOff">The offset in <paramref name="input" /> that the input begins at.</param>
        /// <param name="length">The length of the input starting at <paramref name="inOff" />.</param>
        /// <exception cref="ArgumentOutOfRangeException">An input parameter is out of range (e.g. offset or length is under 0).</exception>
        /// <exception cref="DataLengthException">
        ///     A input or output buffer is of insufficient length.
        /// </exception>
        public virtual void BlockUpdate(byte[] input, int inOff, int length)
        {
            if (input == null)
                throw new ArgumentNullException("input");
            if (inOff < 0)
                throw new ArgumentOutOfRangeException("inOff");
            if (length < 0)
                throw new ArgumentOutOfRangeException("length");
            if ((inOff + length) > input.Length) 
                throw new DataLengthException("Input buffer too short.");
            if (length < 1)
                return;

            BlockUpdateInternal(input, inOff, length);
        }

        /// <summary>
        ///     Compute and output the final state, and reset the internal state of the hash function.
        /// </summary>
        /// <param name="output">Array that the hash is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output" /> that the output is to start at.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">An input parameter is out of range (e.g. offset is under 0).</exception>
        /// <exception cref="DataLengthException">
        ///     A input or output buffer is of insufficient length.
        /// </exception>
        /// <returns>Size of the output in bytes.</returns>
        public virtual int DoFinal(byte[] output, int outOff)
        {
            if (output == null)
                throw new ArgumentNullException("output");
            if (outOff < 0)
                throw new ArgumentOutOfRangeException("outOff");
            if ((outOff + OutputSize) > output.Length) 
                throw new DataLengthException("Output buffer too short.");

            return DoFinalInternal(output, outOff);
        }

        /// <summary>
        ///     Reset the hash function to the same state as it was after instantiation.
        /// </summary>
        public abstract void Reset();

        #endregion

        /// <summary>
        ///     Update the internal state of the hash function with a single byte.
        ///     Performs no checks on state validity - use only when pre-validated!
        /// </summary>
        /// <param name="input">Byte to input.</param>
        protected internal abstract void UpdateInternal(byte input);

        /// <summary>
        ///     Process bytes from <paramref name="input" />.
        ///     Performs no checks on argument or state validity - use only when pre-validated!
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///     The offset in <paramref name="input" /> at which the input data begins.
        /// </param>
        /// <param name="length">The number of bytes to be processed.</param>
        protected internal abstract void BlockUpdateInternal(byte[] input, int inOff, int length);

        /// <summary>
        ///     Compute and output the final state, and reset the internal state of the hash function.
        ///     Performs no checks on argument or state validity - use only when pre-validated!
        /// </summary>
        /// <param name="output">Array that the hash is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output" /> that the output is to start at.
        /// </param>
        /// <returns>Size of the output in bytes.</returns>
        protected internal abstract int DoFinalInternal(byte[] output, int outOff);
    }
}
