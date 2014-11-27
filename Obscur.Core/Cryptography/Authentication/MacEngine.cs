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
    ///     Base class for MAC function implementations.
    /// </summary>
    public abstract class MacEngine : IMac
    {
        /// <summary>
        ///     Type of MAC function, as-per the <see cref="MacFunction" /> enumeration.
        /// </summary>
        protected readonly MacFunction MacIdentity;

        /// <summary>
        ///     If MAC function has been initialised.
        /// </summary>
        protected bool IsInitialised;

        /// <summary>
        ///     Key for the MAC function.
        /// </summary>
        protected byte[] Key;

        /// <summary>
        ///     Instantiate a new MAC function engine.
        /// </summary>
        /// <param name="macIdentity">Identity of the MAC function.</param>
        protected MacEngine(MacFunction macIdentity)
        {
            MacIdentity = macIdentity;
            Key = null;
        }

        /// <summary>
        ///     Display-friendly name of the MAC function.
        /// </summary>
        /// <value>The display name of the MAC function.</value>
        public virtual string DisplayName
        {
            get { return Athena.Cryptography.MacFunctions[MacIdentity].DisplayName; }
        }

        /// <summary>
        ///     The size of operation in bytes the MAC function implements internally, e.g. block buffer.
        /// </summary>
        /// <value>The size of the internal operation in bytes.</value>
        public abstract int StateSize { get; }

        #region IMac Members

        /// <summary>
        ///     The name of the MAC function algorithm,
        ///     including any configuration-specific identifiers.
        /// </summary>
        public virtual string AlgorithmName
        {
            get { return MacIdentity.ToString(); }
        }

        /// <summary>
        ///     Size of output in bytes that the MAC function emits upon finalisation.
        /// </summary>
        public virtual int OutputSize
        {
            get { return Athena.Cryptography.MacFunctions[MacIdentity].OutputSize ?? 0; }
        }

        /// <summary>
        ///     Enumerated identity of the MAC function.
        /// </summary>
        public MacFunction Identity
        {
            get { return MacIdentity; }
        }

        /// <summary>
        ///     Set the initial state of the MAC function. Required before other use.
        /// </summary>
        /// <param name="key">Key for the MAC function.</param>
        /// <exception cref="ArgumentException">
        ///     If the parameter argument is invalid (e.g. incorrect length).
        /// </exception>
        public virtual void Init(byte[] key)
        {
            if (key == null) {
                throw new ArgumentNullException("key", AlgorithmName + " initialisation requires a key.");
            }
            int? correctKeySize = Athena.Cryptography.MacFunctions[MacIdentity].OutputSize;
            if (correctKeySize.HasValue) {
                if (key.Length.BytesToBits() != correctKeySize) {
                    throw new ArgumentException(AlgorithmName + " does not support a " + key.Length + " byte key.");
                }
            }

            this.Key = key;
            this.IsInitialised = true;
            InitState();
        }

        /// <summary>
        ///     Update the internal state of the MAC function with a single byte.
        /// </summary>
        /// <param name="input">Byte to input.</param>
        /// <exception cref="InvalidOperationException">The MAC function is not initialised.</exception>
        public void Update(byte input)
        {
            if (IsInitialised == false) {
                throw new InvalidOperationException(AlgorithmName + " not initialised.");
            }

            UpdateInternal(input);
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
        public void BlockUpdate(byte[] input, int inOff, int length)
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
        public int DoFinal(byte[] output, int outOff)
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
        ///     Reset the MAC function to the same state as it was after the last init (if there was one).
        /// </summary>
        public abstract void Reset();

        #endregion

        /// <summary>
        ///     Update the internal state of the MAC function with a single byte.
        ///     Performs no checks on state validity - use only when pre-validated!
        /// </summary>
        /// <param name="input">Byte to input.</param>
        protected internal abstract void UpdateInternal(byte input);

        /// <summary>
        ///     Set up MAC function's internal state.
        /// </summary>
        protected abstract void InitState();

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
        ///     Compute and output the final state, and reset the internal state of the MAC function.
        ///     Performs no checks on argument or state validity - use only when pre-validated!
        /// </summary>
        /// <param name="output">Array that the MAC is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output" /> that the output is to start at.
        /// </param>
        /// <returns>Size of the output in bytes.</returns>
        protected internal abstract int DoFinalInternal(byte[] output, int outOff);
    }
}
