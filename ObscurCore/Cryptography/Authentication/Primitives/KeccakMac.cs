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

using ObscurCore.Cryptography.Ciphers;

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

		#region IMac implementation

		public void Init (ICipherParameters parameters)
		{
			byte[] key = null, salt = null;
		    var keyParameter = parameters as KeyParameter;
		    if (keyParameter != null) key = keyParameter.GetKey();
		    var parametersWithSalt = parameters as ParametersWithSalt;
		    if (parametersWithSalt != null) salt = parametersWithSalt.GetSalt();
            this.Init(key, salt);
		}

	    public int MacSize {
	        get { return DigestSize; }
	    }

	    #endregion

        /// <summary>
        /// Init the specified key and salt by performing a block update with each sequentially, respectively. 
        /// Values are not stored - therefore, if Reset is called later, and keying and/or salting is required, 
        /// Init must also be called again.
        /// </summary>
        /// <remarks>
        /// It is possible to use keys and salts with Keccak without a HMAC construction 
        /// because it does not suffer from length-extension vulnerabilities.
        /// </remarks>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        public void Init (byte[] key, byte[] salt = null) {
            if (key != null)
                BlockUpdate(key, 0, key.Length);
            if (salt != null)
                BlockUpdate(salt, 0, salt.Length);
        }
	}
}

