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
using System.Text;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    ///     Factory for <see cref="AuthenticationFunctionConfiguration" /> data transfer objects,
    ///     used for configuring the operation of ciphers in a <see cref="MacStream" /> or <see cref="HashStream" />.
    /// </summary>
    /// <remarks>
    ///     Use of a <see cref="AuthenticationFunctionConfiguration" /> is not required for use of 
    ///     a <see cref="MacStream" /> or <see cref="HashStream" />.
    ///     This factory is used for creating MAC configurations for manifests and payload items, for use in packaging.
    /// </remarks>
	public static class AuthenticationConfigurationFactory
	{
		internal const HashFunction DefaultHmacFunction = HashFunction.Blake2B256;
        internal const BlockCipher DefaultCmacCipher = BlockCipher.Aes;
        internal const BlockCipher DefaultPoly1305BlockCipher = BlockCipher.Aes;

		/// <summary>
        /// Creates a new <see cref="AuthenticationFunctionConfiguration" />. 
		/// HMAC, CMAC/OMAC1, or Poly1305 selection will use default basis primitives (BLAKE2B256, AES, and AES, respectively).
		/// </summary>
		/// <remarks>
		/// The MAC configuration generated may be used with a MacStream, 
		/// e.g. package payload item authentication.
		/// </remarks>
        /// <param name="macFunctionEnum">MAC function.</param>
        /// <param name="outputSize">Size of the output from the function in bytes.</param>
        /// <returns>The authentication configuration as a <see cref="AuthenticationFunctionConfiguration" />.</returns>
		public static AuthenticationFunctionConfiguration CreateAuthenticationConfiguration(MacFunction macFunctionEnum, out int outputSize) {
			if (Athena.Cryptography.MacFunctions[macFunctionEnum].OutputSize.HasValue == false) {
				// Either HMAC or CMAC/OMAC1 is being used.
				switch (macFunctionEnum) {
				case MacFunction.Hmac:
					return CreateAuthenticationConfigurationHmac(DefaultHmacFunction, out outputSize);
				case MacFunction.Cmac:
					return CreateAuthenticationConfigurationCmac(DefaultCmacCipher, out outputSize);
				default:
					throw new NotSupportedException();
				}
			}

			if (macFunctionEnum == MacFunction.Poly1305) {
				outputSize = 16;
				return CreateAuthenticationConfigurationPoly1305(DefaultPoly1305BlockCipher);
			}
				
			outputSize = Athena.Cryptography.MacFunctions[macFunctionEnum].OutputSize.Value / 8;

            return CreateAuthConf(macFunctionEnum.ToString(), outputSize * 8, outputSize * 8, null, null);
		}

	    /// <summary>
        /// Creates a <see cref="AuthenticationFunctionConfiguration" /> using a HMAC construction.
	    /// </summary>
	    /// <remarks>
	    /// The HMAC configuration generated may be used with a MacStream, 
	    /// e.g. package payload item authentication.
	    /// </remarks>
	    /// <param name="hashEnum">Hash function to use as basis of the HMAC construction.</param>
        /// <param name="outputSize">Size of the output from the function in bytes.</param>
	    /// <param name="keySize"></param>
        /// <returns>The authentication configuration as a <see cref="AuthenticationFunctionConfiguration" />.</returns>
	    public static AuthenticationFunctionConfiguration CreateAuthenticationConfigurationHmac (HashFunction hashEnum, 
			out int outputSize, int? keySize = null) 
		{
			outputSize = Athena.Cryptography.HashFunctions[hashEnum].OutputSize / 8;
			byte[] functionConfig = Encoding.UTF8.GetBytes(hashEnum.ToString ());
			return CreateAuthConf(MacFunction.Hmac.ToString(), keySize ?? outputSize * 8, outputSize * 8, functionConfig, null);
		}

	    /// <summary>
        /// Creates a <see cref="AuthenticationFunctionConfiguration" /> using a CMAC/OMAC1 construction.
	    /// </summary>
	    /// <remarks>
	    /// The CMAC configuration generated may be used with a MacStream, 
	    /// e.g. package payload item authentication.
	    /// </remarks>
	    /// <param name="cipherEnum">Block cipher to use as basis of the CMAC construction.</param>
	    /// <param name="outputSize">Output size of the CMAC in bytes.</param>
        /// <returns>The authentication configuration as a <see cref="AuthenticationFunctionConfiguration" />.</returns>
	    public static AuthenticationFunctionConfiguration CreateAuthenticationConfigurationCmac(BlockCipher cipherEnum, out int outputSize) {
			outputSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize / 8;
			int keySize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultKeySize;
			byte[] functionConfig = Encoding.UTF8.GetBytes(cipherEnum.ToString());

			return CreateAuthConf(MacFunction.Cmac.ToString(), keySize, outputSize * 8, functionConfig, null);
		}

	    /// <summary>
        /// Creates a <see cref="AuthenticationFunctionConfiguration" /> using a Poly1305-{block cipher} construction, 
	    /// e.g. Poly1305-AES.
	    /// </summary>
	    /// <remarks>
	    /// The Poly1305 configuration generated may be used with a MacStream, 
	    /// e.g. package payload item authentication.
	    /// </remarks>
	    /// <param name="cipherEnum">Block cipher to use as basis of the Poly1305 construction. Must be 128-bit block size.</param>
	    /// <param name="nonce">Nonce to use. If null, it will be randomly generated.</param>
        /// <returns>The authentication configuration as a <see cref="AuthenticationFunctionConfiguration" />.</returns>
	    public static AuthenticationFunctionConfiguration CreateAuthenticationConfigurationPoly1305(BlockCipher cipherEnum, byte[] nonce = null) {
			if (Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize != 128) {
				throw new ArgumentException ("Incompatible cipher block size.");
			}

			byte[] functionConfig = Encoding.UTF8.GetBytes(cipherEnum.ToString ());

			if (nonce == null) {
				nonce = new byte[16];
				StratCom.EntropySupplier.NextBytes (nonce);
			}

			return CreateAuthConf(MacFunction.Poly1305.ToString(), 256, 128, functionConfig, nonce);
		}

		private static AuthenticationFunctionConfiguration CreateAuthConf(string functionName, int keySizeBits, int outputSizeBits, byte[] functionConfig, byte[] nonce) {
			var config = new AuthenticationFunctionConfiguration {
				FunctionType = AuthenticationFunctionType.Mac.ToString(),
				FunctionName = functionName,
				FunctionConfiguration = functionConfig,
				KeySizeBits = keySizeBits,
				Nonce = nonce,
				Salt = new byte[outputSizeBits / 8]
			};
			StratCom.EntropySupplier.NextBytes(config.Salt);
			return config;
		}
	}
}
