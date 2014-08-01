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

using System;
using System.Collections.Generic;

namespace ObscurCore.Cryptography.KeyDerivation
{
    /// <summary>
    ///     Factory for key derivation primitives.
    /// </summary>
	public static class KdfFactory
	{
		private readonly static IDictionary<KeyDerivationFunction, Func<int, byte[], IKdfFunction>> KdfInstantiators =
			new Dictionary<KeyDerivationFunction, Func<int, byte[], IKdfFunction>>();

		private readonly static IDictionary<KeyDerivationFunction, Func<byte[], byte[], int, byte[], byte[]>> KdfStatics =
			new Dictionary<KeyDerivationFunction, Func<byte[], byte[], int, byte[], byte[]>>();

		/// <summary>
		/// Derives a working key with the KDF module.
		/// </summary>
		/// <returns>The working key.</returns>
		/// <param name="kdfEnum">Key derivation function to use.</param>
		/// <param name="key">Pre-key to use as input material.</param>
		/// <param name="salt">Salt to use in derivation to increase entropy.</param>
		/// <param name="outputSize">Output key size in bytes.</param>
		/// <param name="config">Serialised configuration of the KDF.</param>
		public static byte[] DeriveKeyWithKdf (KeyDerivationFunction kdfEnum, byte[] key, byte[] salt, int outputSize, byte[] config) {
			return KdfStatics[kdfEnum](key, salt, outputSize, config);
		}

		public static IKdfFunction CreateKdf(KeyDerivationFunction kdfEnum, int outputSize, byte[] config) {
			return KdfInstantiators[kdfEnum](outputSize, config);
		}

		static KdfFactory ()
		{
			KdfInstantiators.Add(KeyDerivationFunction.Pbkdf2, (outputSize, config) => new Pbkdf2Module(outputSize, config));
			KdfInstantiators.Add(KeyDerivationFunction.Scrypt, (outputSize, config) => new ScryptModule(outputSize, config));

			KdfStatics.Add(KeyDerivationFunction.Pbkdf2, Pbkdf2Module.DeriveKeyWithConfig);
			KdfStatics.Add(KeyDerivationFunction.Scrypt, ScryptModule.DeriveKeyWithConfig);
		}
	}
}

