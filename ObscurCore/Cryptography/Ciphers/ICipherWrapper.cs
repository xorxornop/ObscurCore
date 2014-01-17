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
    interface ICipherWrapper
    {
        bool Encrypting { get; }
        int OperationSize { get; }

		/// <summary>
		/// Description/name of the cipher construction, e.g. AES/CTR, or Blowfish/CBC/PKCS7.
		/// </summary>
		/// <value>The name of the algorithm.</value>
		string AlgorithmName { get; }

        int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset);

		int ProcessFinal(byte[] input, int inputOffset, int length, byte[] output, int outputOffset);

		void Reset();
    }
}