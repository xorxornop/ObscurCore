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
	public interface ICipherWrapper
    {
        bool Encrypting { get; }

		/// <summary>
		/// The size of each discrete cipher operation in bytes. 
		/// Calls may fail or have undefined behaviour if ProcessBytes(...) 
		/// is called with sizes other than this. ProcessFinal calls can be 
		/// this size or shorter.
		/// </summary>
		/// <value>The size of a cipher operation.</value>
        int OperationSize { get; }

		/// <summary>
		/// Description/name of the cipher construction, e.g. AES/CTR, Blowfish/CBC/PKCS7, 
		/// or XSalsa20 etc.
		/// </summary>
		/// <value>The name of the cipher algorithm.</value>
		string AlgorithmName { get; }

        int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset);

		int ProcessFinal(byte[] input, int inputOffset, int length, byte[] output, int outputOffset);

		void Reset();
    }
}