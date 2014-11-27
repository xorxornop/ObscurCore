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

using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.KeyDerivation.Primitives;
using Obscur.Core.DTO;

namespace Obscur.Core.Cryptography.KeyDerivation
{
	/// <summary>
	/// Derives cryptographic keys using the PBKDF2 function.
	/// </summary>
	public sealed class Pbkdf2Module : IKdfFunction
	{
		private readonly int _outputSize, _iterations;
	    private HashFunction _function;

        public const int DefaultIterations = 32768, MinimumIterations = 512, MaximumIterations = 1048576;
		internal const HashFunction DefaultFunction = HashFunction.Sha256;
		
		public Pbkdf2Module (int outputSize, byte[] config) {
			_outputSize = outputSize;
		    var configObj = config.DeserialiseDto<Pbkdf2Configuration>();
		    _iterations = configObj.Iterations;
		    _function = configObj.FunctionName.ToEnum<HashFunction>();
		}
		
		#region IKDFModule implementation
		public byte[] DeriveKey (byte[] key, byte[] salt) {
			return DeriveKey(key, salt, _outputSize, _iterations);
		}

		public byte[] DeriveKey (byte[] key, byte[] salt, int outputSize) {
			return DeriveKey(key, salt, outputSize, _iterations);
		}

		public byte[] DeriveKey (byte[] key, byte[] salt, byte[] config) {
			return DeriveKeyWithConfig(key, salt, _outputSize, config);
		}

		public byte[] DeriveKey (byte[] key, byte[] salt, int outputSize, byte[] config) {
			return DeriveKeyWithConfig(key, salt, outputSize, config);
		}

        public byte[] DeriveKey(byte[] key, int outputSize, KeyDerivationConfiguration config) {
            return DeriveKeyWithConfig(key, config.Salt, outputSize, config.FunctionConfiguration);
        }
		#endregion
		
		private static byte[] DeriveKey (byte[] key, byte[] salt, int outputSize, int iterations) {
			var hmac = AuthenticatorFactory.CreateHmacPrimitive(DefaultFunction, key, null);
			return Pbkdf2.ComputeDerivedKey(hmac, salt, iterations, outputSize);
		}
		
		public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, byte[] config) {
            var configObj = config.DeserialiseDto<Pbkdf2Configuration>();
            return DeriveKeyWithConfig(key, salt, outputSize, configObj);
		}

        public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, Pbkdf2Configuration config) {
			var hmac = AuthenticatorFactory.CreateHmacPrimitive(config.FunctionName.ToEnum<HashFunction>(), key, null);
			return Pbkdf2.ComputeDerivedKey(hmac, salt, config.Iterations, outputSize);
		}
	}
}
