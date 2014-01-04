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
using ObscurCore.Cryptography.Authentication.Primitives.BLAKE2B;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	public sealed class Blake2BMac : Blake2BDigest, IMac
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.Cryptography.MACs.Blake2BMac"/> class.
		/// </summary>
		/// <param name="size">Size of the MAC to produce.</param>
		/// <param name="bits">Whether <paramref name="size"/> is interpreted as bits or bytes. If true, bits.</param>
		public Blake2BMac (int size, bool bits) : base(size, bits, false)
		{
		}

		#region IMac implementation

		public void Init (ICipherParameters parameters)
		{
			this.Init (parameters, null);
		}

		/// <summary>
		/// Initialise the MAC primitive with a key and/or salt and/or a tag.
		/// </summary>
		/// <param name="parameters">Parameter object that may comprise a key and/or salt. Key maximum 64 bytes, salt 16.</param>
		/// <param name="tag">Tag/personalisation to include in the IV for the MAC. 16 bytes maximum.</param>
		public void Init(ICipherParameters parameters, byte[] tag) {
			byte[] key = null, salt = null;
		    var keyParameter = parameters as KeyParameter;
		    if (keyParameter != null) key = keyParameter.GetKey();
		    var parametersWithSalt = parameters as ParametersWithSalt;
		    if (parametersWithSalt != null) salt = parametersWithSalt.GetSalt();
			this.Init (key, salt, tag);
		}

		public void Init(byte[] key, byte[] salt, byte[] tag) {
			byte[] keyBytes = null, saltBytes = null, tagBytes = null;

			if(key != null) {
				if(key.Length > 64) throw new ArgumentOutOfRangeException("key", "Key is longer than 64 bytes.");
				keyBytes = new byte[key.Length];
				Array.Copy(key, keyBytes, key.Length);
			}

			if(salt != null) {
				if(salt.Length > 16) throw new ArgumentOutOfRangeException("salt", "Salt is longer than 16 bytes.");
				saltBytes = new byte[16];
				Array.Copy(salt, saltBytes, salt.Length);
			}

			if(tag != null) {
				if(tag.Length > 16) throw new ArgumentOutOfRangeException("tag", "Tag is longer than 16 bytes.");
				tagBytes = new byte[16];
                Array.Copy(tag, tagBytes, tag.Length);
			}

			var config = new Blake2BConfig () {
				Key = keyBytes,
				Salt = saltBytes,
				Personalization = tagBytes,
				OutputSizeInBytes = outputSize,
			};

			base.InitCore (config);
		}

		public void Init(byte[] key, byte[] salt) {
			this.Init (key, salt, null);
		}

	    public int MacSize {
	        get { return this.DigestSize; }
	    }

	    #endregion
    }
}

