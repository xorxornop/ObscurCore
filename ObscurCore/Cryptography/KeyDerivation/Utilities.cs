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
using System.IO;
using ObscurCore.Extensions.Generic;
using ObscurCore.Extensions.Streams;

namespace ObscurCore.Cryptography.KeyDerivation
{
	public static class ScryptConfigurationUtility
	{	
		public const int DefaultIterationPower = 16, DefaultBlocks = 8, DefaultParallelisation = 2;
		internal const string DefaultAlgorithm = "HMACSHA256";
		
		/// <summary>
		/// Reads an scrypt configuration from shorthand byte array format, and outputs the 
		/// iterationPower, blocks and parallelisation parameters to external variable fields.
		/// </summary>
		/// <param name="config">Byte array containing the configuration.</param>
		/// <param name='iterationPower'>
		/// Power to raise the iteration count by - i.e. 2^n iterations, where n is <paramref name="iterationPower"/>. 
		/// General-use cost increase. Use to scale cost/difficulty without changing CPU or memory cost directly, only time.
		/// </param>
		/// <param name='blocks'>
		/// Blocks to operate on. Increases memory cost, as this algorithm is memory-hard. 
		/// Use sparingly in constrained environment such as mobile. Scale according to memory advancements.
		/// </param>
		/// <param name='parallelisation'>
		/// How many co-dependant mix operations must be performed. 
		/// Can be run in parallel, hence the name. Increases CPU cost. Scale according to CPU speed advancements.
		/// </param>
		public static void Read(byte[] config, out int iterationPower, out int blocks, out int parallelisation) {
			string algorithm;
		    using (var ms = new MemoryStream(config)) {
				byte _iterationPower, _blocks, _parallelisation;
		        ms.ReadPrimitive(out _iterationPower);
                ms.ReadPrimitive(out _blocks);
                ms.ReadPrimitive(out _parallelisation);
				ms.ReadPrimitive(out algorithm);
				
				iterationPower = (int)_iterationPower;
				blocks = (int)_blocks;
				parallelisation = (int)_parallelisation;
		    }
            if(!iterationPower.IsBetween(5, 20)) throw new ArgumentOutOfRangeException("iterationPower", "Power to raise the iteration count (iterations = n^power) of scrypt KDF is out of the range of 5 to 20.");
			if(!algorithm.Equals(DefaultAlgorithm)) 
				throw new NotSupportedException("Only " + DefaultAlgorithm + " allowed currently.");		
		}
		
		/// <summary>
		/// Writes an scrypt configuration in shorthand byte array format with the 
		/// specified iterationPower, blocks and parallelisation parameters.
		/// </summary>
		/// <param name='iterationPower'>
		/// Power to raise the iteration count by, e.g. 2^n iterations where n is 'iterationPower'. 
		/// General-use cost increase. Use to scale cost/difficulty without changing CPU or memory cost directly, only time.
		/// </param>
		/// <param name='blocks'>
		/// Blocks to operate on. Increases memory cost, as this algorithm is memory-hard. 
		/// Use sparingly in constrained environment such as mobile. Scale according to memory advancements.
		/// </param>
		/// <param name='parallelisation'>
		/// How many co-dependant mix operations must be performed. 
		/// Can be run in parallel, hence the name. Increases CPU cost. Scale according to CPU speed advancements.
		/// </param>
		/// <param name="output">Byte array containing the configuration.</param>
		public static void Write(int iterationPower, int blocks, int parallelisation, out byte[] output) {
            // TODO: Check parameter validity.
            using (var ms = new MemoryStream()) {
                ms.WritePrimitive((byte)iterationPower);
                ms.WritePrimitive((byte)blocks);
                ms.WritePrimitive((byte)parallelisation);
				ms.WritePrimitive(DefaultAlgorithm); // write the algorithm name even though we can't change it ATM.
                output = ms.ToArray();
            }
		}
		
		public static byte[] Write(int iterationPower, int blocks, int parallelisation) {
			byte[] output;
			Write(iterationPower, blocks, parallelisation, out output);
			return output;
		}
	}
	
	public static class PBKDF2ConfigurationUtility
	{	
		public const int DefaultIterations = 32768, MinimumIterations = 512, MaximumIterations = 1048576;
		internal const string DefaultAlgorithm = "HMACSHA256";
		
		/// <summary>
		/// Reads a PBKDF2 configuration from shorthand byte array format, and outputs the 
		/// iterationPower, blocks and parallelisation parameters to external variable fields.
		/// </summary>
		/// <param name="config">Byte array containing the configuration.</param>
		/// <param name='iterations'>
		/// Number of successive hashes to perform. The first hash is {key+salt}. Latter hashes are {n-1+salt}.
		/// General-use cost increase. Use to scale time taken to perform the function with CPU speed advancements.
		/// </param>
		public static void Read (byte[] config, out int iterations) {
			string algorithm;
			using (var ms = new MemoryStream(config)) {
				ms.ReadPrimitive (out iterations);
				ms.ReadPrimitive (out algorithm);
			}
			if (!iterations.IsBetween<int> (MinimumIterations, MaximumIterations)) {
				throw new ArgumentOutOfRangeException ("iterations", 
				String.Format ("Number of iterations specified is out of the range of {0} to {1}.", 
				MinimumIterations, MaximumIterations));
			}
			if(!algorithm.Equals(DefaultAlgorithm)) 
				throw new NotSupportedException("Only " + DefaultAlgorithm + " allowed currently.");
		}
		
		/// <summary>
		/// Writes a PBKDF2 configuration in shorthand byte array format.
		/// </summary>
		/// <param name='iterations'>
		/// Number of successive hashes to perform. The first hash is {key+salt}. Latter hashes are {n-1+salt}.
		/// General-use cost increase. Use to scale time taken to perform the function with CPU speed advancements.
		/// </param>
		/// <param name="output">Byte array containing the configuration.</param>
		public static void Write(int iterations, out byte[] output) {
			// TODO: Check parameter validity.
			using (var ms = new MemoryStream()) {
				ms.WritePrimitive(iterations);
				ms.WritePrimitive(DefaultAlgorithm); // write the algorithm name even though we can't change it ATM.
				output = ms.ToArray();
			}
		}
		
		public static byte[] Write(int iterations) {
			byte[] output;
			Write(iterations, out output);
			return output;
		}
	}
	
	
}

