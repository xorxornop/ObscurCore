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
using System.Security.Cryptography;
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

        public const int DefaultIterationPower = 16, DefaultBlocks = 8, DefaultParallelisation = 2;

	    public ScryptModule (int outputSize, byte[] config) {
			_outputSize = outputSize;
	        var configObj = StratCom.DeserialiseDTO<ScryptConfiguration>(config);
	        _iterationPower = configObj.IterationPower;
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
            return DeriveKeyWithConfig(key, config.Salt, outputSize, config.SchemeConfiguration);
        }
		#endregion		
		
		private static byte[] DeriveKey (byte[] key, byte[] salt, int outputSize, int iterationPower, int blocks, int parallelisation) {
			var output = new byte[outputSize / 8];
			SCrypt.ComputeKey(key, salt, iterationPower, blocks, parallelisation, null, output);
			return output;
		}
		
		public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, byte[] config) {
		    var scConfig = StratCom.DeserialiseDTO<ScryptConfiguration>(config);
			var output = new byte[outputSize / 8];
			SCrypt.ComputeKey(key, salt, scConfig.IterationPower, scConfig.Blocks, scConfig.Parallelism, null, output);
			return output;
		}

        public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, ScryptConfiguration config) {
			var output = new byte[outputSize / 8];
			SCrypt.ComputeKey(key, salt, config.IterationPower, config.Blocks, config.Parallelism, null, output);
			return output;
		}
	}

	/// <summary>
	/// Derives cryptographic keys using the PBKDF2 function.
	/// </summary>
	public sealed class Pbkdf2Module : IKdfFunction
	{
		private readonly int _outputSize, _iterations;
	    private string _algorithm;

        public const int DefaultIterations = 32768, MinimumIterations = 512, MaximumIterations = 1048576;
		internal const string DefaultAlgorithm = "HMACSHA256";
		
		public Pbkdf2Module (int outputSize, byte[] config) {
			_outputSize = outputSize;
            var pbkdf2Config = StratCom.DeserialiseDTO<PBKDF2Configuration>(config);
		    _iterations = pbkdf2Config.Iterations;
		    _algorithm = pbkdf2Config.AlgorithmName;
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
            return DeriveKeyWithConfig(key, config.Salt, outputSize, config.SchemeConfiguration);
        }
		#endregion
		
		private static byte[] DeriveKey (byte[] key, byte[] salt, int outputSize, int iterations) {
			var output = new byte[outputSize];
			Pbkdf2.ComputeKey(key, salt, iterations, Pbkdf2.CallbackFromHmac<HMACSHA256>(), outputSize / 8, output);
			return output;
		}
		
		public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, byte[] config) {
			var pbkdf2Config = StratCom.DeserialiseDTO<PBKDF2Configuration>(config);
            if(!pbkdf2Config.AlgorithmName.Equals("HMACSHA256")) throw new ArgumentException();
			var output = new byte[outputSize];
			Pbkdf2.ComputeKey(key, salt, pbkdf2Config.Iterations, Pbkdf2.CallbackFromHmac<HMACSHA256>(), outputSize / 8, output);
			return output;
		}

        public static byte[] DeriveKeyWithConfig(byte[] key, byte[] salt, int outputSize, PBKDF2Configuration config) {
            if(!config.AlgorithmName.Equals("HMACSHA256")) throw new ArgumentException();
			var output = new byte[outputSize];
			Pbkdf2.ComputeKey(key, salt, config.Iterations, Pbkdf2.CallbackFromHmac<HMACSHA256>(), outputSize / 8, output);
			return output;
		}
	}
}

