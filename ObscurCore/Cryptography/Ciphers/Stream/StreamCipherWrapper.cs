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

using System;

namespace ObscurCore.Cryptography.Ciphers.Stream
{
	/// <summary>
	/// Provides a wrapper for I/O operations with stream ciphers.
	/// </summary>
	/// <remarks>
	/// No buffering support is included for performance and precise control. 
	/// All I/O operations must therefore be tailored to cipher block size. 
	/// Similarly, a minimum of error-checking is done, and so should be done by the caller.
	/// </remarks>
	public sealed class StreamCipherWrapper : ICipherWrapper
	{
		private readonly IStreamCipher _cipher;
		private readonly int _strideSize;

		public bool Encrypting { get; private set; }

		public int OperationSize { get { return _strideSize; } }

		public string AlgorithmName { get { return _cipher.AlgorithmName; } }

		/// <summary>
		/// Initializes a new <see cref="ObscurCore.Cryptography.Ciphers.Stream.StreamCipherWrapper"/>.
		/// </summary>
		/// <param name="encrypting">If set to <c>true</c> encrypting.</param>
		/// <param name="cipher">Cipher to wrap (must be pre-initialised).</param>
		/// <param name="strideIncreaseFactor">Power to raise operation size by.</param>
		public StreamCipherWrapper (bool encrypting, IStreamCipher cipher, int strideIncreaseFactor = 0)
		{
			if(cipher == null) {
				throw new ArgumentNullException ("cipher");
			}
		    if(strideIncreaseFactor < 0 || strideIncreaseFactor > 8) {
		        throw new ArgumentOutOfRangeException ("strideIncreaseFactor");
		    }

		    Encrypting = encrypting;
			_cipher = cipher;
			_strideSize = _cipher.StateSize << strideIncreaseFactor;
		}

		/// <summary>
		/// Process a stride of plaintext/ciphertext into the opposite form.
		/// </summary>
		/// <param name="input">Array to take input bytes from.</param>
		/// <param name="inputOffset">Position at which to read from.</param>
		/// <param name="output">Array to put output bytes in.</param>
		/// <param name="outputOffset">Position at which to write to.</param>
		public int ProcessBytes (byte[] input, int inputOffset, byte[] output, int outputOffset) {
			_cipher.ProcessBytes (input, inputOffset, _strideSize, output, outputOffset);
			return _strideSize;
		}

		public int ProcessFinal (byte[] input, int inputOffset, int length, byte[] output, int outputOffset) {
			if (length == 0)
				return 0;
			_cipher.ProcessBytes (input, inputOffset, length, output, outputOffset);
			return length;
		}

		public void Reset () {
			_cipher.Reset ();
		}
	}
}
