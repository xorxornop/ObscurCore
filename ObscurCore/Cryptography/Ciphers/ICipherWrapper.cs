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

namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    ///     Standard interface for cipher wrapper types to implement.
    /// </summary>
    public interface ICipherWrapper
    {
        bool Encrypting { get; }

        /// <summary>
        ///     The size of each discrete cipher operation in bytes.
        ///     Calls may fail or have undefined behaviour if ProcessBytes(...)
        ///     is called with sizes other than this. ProcessFinal calls can be
        ///     this size or shorter.
        /// </summary>
        /// <value>The size of a cipher operation in bytes.</value>
        int OperationSize { get; }

        /// <summary>
        ///     Description/name of the cipher construction, e.g. AES/CTR, Blowfish/CBC/PKCS7,
        ///     or XSalsa20 etc.
        /// </summary>
        /// <value>The name of the cipher algorithm.</value>
        string AlgorithmName { get; }

        /// <summary>
        ///     Encrypt/decrypt exactly <see cref="OperationSize"/> bytes from <paramref name="input"/> 
        ///     and put the result into <paramref name="output"/>.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inputOffset">
        ///     The offset in <paramref name="input"/> at which the input data begins.
        /// </param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outputOffset">
        ///     The offset in <paramref name="output"/> at which to write the output data to.
        /// </param>
        /// <returns>Number of bytes written to <paramref name="output"/> as result of operation.</returns>
        /// <exception cref="DataLengthException">
        ///     If input or output buffers are of insufficient length to read/write input/output.
        /// </exception>
        int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset);

        /// <summary>
        ///     Encrypt/decrypt cipher final bytes from <paramref name="input"/> 
        ///     and put the result into <paramref name="output"/>. Used at the end of plaintext/ciphertext, 
        ///     where data length is less than or equal to <see cref="OperationSize"/>.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inputOffset">
        ///     The offset in <paramref name="input"/> at which the input data begins.
        /// </param>
        /// <param name="length">The number of bytes constituting the final operation.</param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outputOffset">
        ///     The offset in <paramref name="output"/> at which to write the output data to.
        /// </param>
        /// <returns>Number of bytes written to <paramref name="output"/> as result of operation.</returns>
        /// <exception cref="DataLengthException">
        ///     If input or output buffers are of insufficient length to read/write input/output.
        /// </exception>
        int ProcessFinal(byte[] input, int inputOffset, int length, byte[] output, int outputOffset);

        /// <summary>
        ///     Reset the cipher to the same state as it was after instantiation.
        /// </summary>
        void Reset();
    }
}
