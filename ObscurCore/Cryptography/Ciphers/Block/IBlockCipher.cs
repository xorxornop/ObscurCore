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

namespace ObscurCore.Cryptography.Ciphers.Block
{
	/// <summary>
	/// Interface that block ciphers conform to.
	/// </summary>
    public interface IBlockCipher
    {
		/// <summary>
		/// Name of the algorithm(s) that the cipher implements, 
		/// in order of their implementation. For example, this may 
		/// include modes and paddings implemented on ciphers, e.g. 
		/// AES/CTR (no padding), or AES/CBC/PKCS7 (padded).
		/// </summary>
		string AlgorithmName { get; }

		/// <summary>
		/// Initialise the cipher. Depending on the construction, an initialisation 
		/// vector may also be required to be supplied.
		/// </summary>
		/// <param name="encrypting">If set to <c>true</c> encrypting, otherwise decrypting.</param>
		/// <param name="key">Key for the cipher (required).</param>
		/// <param name="iv">Initialisation vector, if used.</param>
		void Init (bool encrypting, byte[] key, byte[] iv);

	    /// <value>Block size for this cipher in bytes.</value>
	    int BlockSize { get; }

		/// <summary>Whether this cipher can handle partial blocks.</summary>
		bool IsPartialBlockOkay { get; }

		/// <summary>
		/// Process one block of input from the array in and write it to the out array.
		/// </summary>
		/// <param name="input">The input buffer.</param>
		/// <param name="inOff">The offset into <paramref>input</paramref> that the input block begins.</param>
		/// <param name="output">The output buffer.</param>
		/// <param name="outOff">The offset into <paramref>output</paramref> to write the output block.</param>
		/// <exception cref="DataLengthException">
		/// If input or output buffers are of insufficient length to read/write input/output.
		/// </exception>
		/// <returns>The number of bytes put in output.</returns>
		int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff);

		/// <summary>
		/// Reset the cipher to the same state as it was after the last init (if there was one).
		/// </summary>
        void Reset();
    }
}
