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
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.Extensions.Generic;
using ObscurCore.Extensions.Streams;

namespace ObscurCore.Cryptography.Entropy
{
	public static class Salsa20GeneratorConfigurationUtility
	{
		/// <summary>
		/// Reads a <see cref="Salsa20Generator"/> PRNG configuration from shorthand byte array format. 
		/// </summary>
		/// <param name='config'>
		/// Config byte array.
		/// </param>
		/// <param name='iv'>
		/// Initialisation vector for the Salsa20 cipher.
		/// </param>
		/// <param name='key'>
		/// Key for the Salsa20 cipher.
		/// </param>
		public static void Read(byte[] config, out byte[] iv, out byte[] key) {
			if (config.Length == 0) throw new ArgumentException("Configuration is invalid, no data found!");
			using (var ms = new MemoryStream(config))
			{
				ms.ReadPrimitive(out iv);
				ms.ReadPrimitive(out key);
			}
			if (iv.Length != 8) throw new ArgumentException("IV is not 8 bytes in length.", "iv");
			if (!key.Length.IsBetween(12, 32)) throw new ArgumentOutOfRangeException("key", "Key is not between 12 and 32 bytes in length.");
		}
		
		/// <summary>
		/// Writes a <see cref="Salsa20Generator"/> PRNG configuration in shorthand byte array format, 
		/// using a pre-generated IV and key for the cipher.
		/// </summary>
		/// <returns>Byte array containing the configuration with known IV and key.</returns>
		/// <param name='iv'>
		/// Initialisation vector for the Salsa20 cipher.
		/// </param>
		/// <param name='key'>
		/// Key for the Salsa20 cipher.
		/// </param>
		public static byte[] WritePregenerated(byte[] iv, byte[] key) {
			if (iv.Length != 8) throw new ArgumentException("IV provided is not 8 bytes in length.", "iv");
			if (!key.Length.IsBetween(12, 32)) throw new ArgumentOutOfRangeException("key", "Key provided is not between 12 and 32 bytes in length.");
			
			var ms = new MemoryStream();
			ms.WritePrimitive(iv);
			ms.WritePrimitive(key);
			return ms.ToArray();
		}
		
        /// <summary>
        /// Writes a <see cref="Salsa20Generator"/> PRNG configuration in shorthand byte array format, 
        /// generating random IV and 256-bit key for the cipher on the fly.
        /// </summary>
        /// <returns>Byte array containing the configuration with random IV and key.</returns>
        public static byte[] WriteRandom() {
            var secureRandom = StratCom.EntropySource;
            byte[] iv = new byte[8], key = new byte[32];
            secureRandom.NextBytes(iv);
            secureRandom.NextBytes(key);
            return WritePregenerated(iv, key);
        }
	}

	public static class SOSEMANUKGeneratorConfigurationUtility
	{
		/// <summary>
		/// Reads a <see cref="SOSEMANUKGenerator"/> PRNG configuration from shorthand byte array format. 
		/// </summary>
		/// <param name='config'>
		/// Config byte array.
		/// </param>
		/// <param name='iv'>
		/// Initialisation vector (IV) for the SOSEMANUK cipher.
		/// </param>
		/// <param name='key'>
		/// Key for the SOSEMANUK cipher.
		/// </param>
		public static void Read(byte[] config, out byte[] iv, out byte[] key) {
			if (config.Length == 0) throw new ArgumentException("Configuration is invalid, no data found!");
			using (var ms = new MemoryStream(config))
			{
				ms.ReadPrimitive(out iv);
				ms.ReadPrimitive(out key);
			}
			if (iv.Length != 16) throw new ArgumentException("IV is not 16 bytes in length.", "iv");
			if (key.Length != 32) throw new ArgumentOutOfRangeException("key", "Key is not 32 bytes in length.");
		}
		
		/// <summary>
		/// Writes a <see cref="SOSEMANUKGenerator"/> PRNG configuration in shorthand byte array format, 
		/// using a pre-generated IV and key for the cipher.
		/// </summary>
		/// <returns>Byte array containing the configuration with known IV and key.</returns>
		/// <param name='iv'>
		/// Initialisation vector for the SOSEMANUK cipher.
		/// </param>
		/// <param name='key'>
		/// Key for the SOSEMANUK cipher.
		/// </param>
		public static byte[] WritePregenerated(byte[] iv, byte[] key) {
			if (iv.Length != 16) throw new ArgumentException("IV provided is not 16 bytes in length.", "iv");
			if (key.Length != 32) throw new ArgumentOutOfRangeException("key", "Key provided is not between 12 and 32 bytes in length.");
			
			var ms = new MemoryStream();
			ms.WritePrimitive(iv);
			ms.WritePrimitive(key);
			return ms.ToArray();
		}
		
        /// <summary>
        /// Writes a <see cref="Salsa20Generator"/> PRNG configuration in shorthand byte array format, 
        /// generating random IV and 256-bit key for the cipher on the fly.
        /// </summary>
        /// <returns>Byte array containing the configuration with random IV and key.</returns>
        public static byte[] WriteRandom() {
            var secureRandom = StratCom.EntropySource;
            byte[] iv = new byte[16], key = new byte[32];
            secureRandom.NextBytes(iv);
            secureRandom.NextBytes(key);
            return WritePregenerated(iv, key);
        }
	}
}

