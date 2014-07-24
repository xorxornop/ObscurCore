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

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	/// <summary>
	/// Keccak (SHA3) algorithm implemented as a Message Authentication Code (MAC). Variable output size.
	/// </summary>
    public class KeccakMac : KeccakDigest, IMac
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.Cryptography.Authentication.Primitives.KeccakMac"/> class.
		/// </summary>
		/// <param name="size">Size of the MAC produced in bytes. Supported sizes are 28, 32, 48, and 64.</param>
		/// <param name="bits">Whether <paramref name="size"/> is interpreted as bits or bytes. If true, bits.</param>
		public KeccakMac (int size, bool bits) : base(size, bits)
		{
		}

	    public int MacSize {
	        get { return DigestSize; }
	    }

		public void Init (byte[] key) {
			if (key.IsNullOrZeroLength() == false) {
				BlockUpdate(key, 0, key.Length);
			}
		}
	}
}

