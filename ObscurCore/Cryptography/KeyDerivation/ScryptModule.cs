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
using ObscurCore.Cryptography.KeyDerivation.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyDerivation
{
    /// <summary>
	/// Derives cryptographic keys using the scrypt key derivation function. 
	/// </summary>
	public sealed class ScryptModule : IKdfFunction
	{
		private readonly int _outputSize, _iterationPower, _blocks, _parallelisation;

		public const int DefaultIterations = 16384, DefaultBlocks = 8, DefaultParallelisation = 2;

	    public ScryptModule (int outputSize, byte[] config) {
			_outputSize = outputSize;
	        var configObj = StratCom.DeserialiseDataTransferObject<ScryptConfiguration>(config);
	        _iterationPower = configObj.Iterations;
	        _blocks = configObj.Blocks;
	        _parallelisation = configObj.Parallelism;
	    }
		
		public ScryptModule (int outputSize, int iterationPower, int blocks, int parallelisation) {
			_outputSize = outputSize;
			_iterationPower = iterationPower;
			_blocks = blocks;
			_parallelisation = parallelisation;
		}

		#region IKDFModule implementation
		public byte[] DeriveKey (byte[] key, byte[] salt) {
			return DeriveKey(key, salt, _outputSize, _iterationPower, _blocks, _parallelisation);
		}
		
		public byte[] DeriveKey (byte[] key, byte[] salt, int outputSize) {
			return DeriveKey(key, salt, outputSize, _iterationPower, _blocks, _parallelisation);
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

		private static byte[] DeriveKey (byte[] key, byte[] salt, int outputSize, int iterationPower, int blocks, int parallelisation) {
			return Scrypt.ComputeDerivedKey (key, salt, iterationPower, blocks, parallelisation, null, outputSize);
		}
		
		public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, byte[] config) {
		    var scConfig = StratCom.DeserialiseDataTransferObject<ScryptConfiguration>(config);
			return DeriveKeyWithConfig (key, salt, outputSize, scConfig);
		}

        public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, ScryptConfiguration config) {
			return Scrypt.ComputeDerivedKey (key, salt, config.Iterations, config.Blocks, config.Parallelism, null, outputSize);
		}
	}
	
}
