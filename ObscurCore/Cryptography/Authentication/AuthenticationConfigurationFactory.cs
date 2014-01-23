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
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Authentication
{
	public static class AuthenticationConfigurationFactory
	{
		const MacFunction DefaultMacFunction = MacFunction.Blake2B256;
		const HashFunction DefaultHmacFunction = HashFunction.Blake2B256;
		const SymmetricBlockCipher DefaultCmacCipher = SymmetricBlockCipher.Aes;
		const SymmetricBlockCipher DefaultPoly1305Cipher = SymmetricBlockCipher.Aes;

		/// <summary>
		/// Creates a new authentication configuration. 
		/// HMAC or CMAC/OMAC1 selection will use default basis primitives (BLAKE2B256 or AES, respectively).
		/// </summary>
		/// <remarks>
		/// The MAC configuration generated may be used with a MacStream, 
		/// e.g. package payload item authentication.
		/// </remarks>
		/// <returns>The authentication configuration as a VerificationFunctionConfiguration.</returns>
		/// <param name="macFEnum">Mac F enum.</param>
		public static VerificationFunctionConfiguration CreateAuthenticationConfiguration(MacFunction macFEnum = DefaultMacFunction) {
			if (!Athena.Cryptography.MacFunctions [DefaultMacFunction].OutputSize.HasValue) {
				// Either HMAC or CMAC/OMAC1 is being used.
				switch (macFEnum) {
				case MacFunction.Hmac:
					return CreateAuthenticationConfigurationHmac ();
				case MacFunction.Cmac:
					return CreateAuthenticationConfigurationCmac ();
				case MacFunction.Poly1305:
					return CreateAuthenticationConfigurationPoly1305 ();
				default:
					throw new NotImplementedException ();
				}
			}
			return CreateAuthConf (macFEnum.ToString (), 
				Athena.Cryptography.MacFunctions [DefaultMacFunction].OutputSize.Value / 8, null);
		}

		/// <summary>
		/// Creates a new authentication configuration using HMAC construction.
		/// </summary>
		/// <remarks>
		/// The HMAC configuration generated may be used with a MacStream, 
		/// e.g. package payload item authentication.
		/// </remarks>
		/// <returns>The authentication configuration as a VerificationFunctionConfiguration.</returns>
		/// <param name="hmacEnum">Hmac enum.</param>
		public static VerificationFunctionConfiguration CreateAuthenticationConfigurationHmac(HashFunction hmacEnum = DefaultHmacFunction) {
			int outputSize = Athena.Cryptography.HashFunctions[hmacEnum].OutputSize;
			byte[] functionConfig = Encoding.UTF8.GetBytes (hmacEnum.ToString ());
			return CreateAuthConf(MacFunction.Hmac.ToString(), outputSize / 8, functionConfig);
		}

		/// <summary>
		/// Creates a new authentication configuration using CMAC/OMAC1 construction.
		/// </summary>
		/// <remarks>
		/// The CMAC configuration generated may be used with a MacStream, 
		/// e.g. package payload item authentication.
		/// </remarks>
		/// <returns>The authentication configuration as a VerificationFunctionConfiguration.</returns>
		/// <param name="cmacEnum">Cmac enum.</param>
		public static VerificationFunctionConfiguration CreateAuthenticationConfigurationCmac(SymmetricBlockCipher cmacEnum = DefaultCmacCipher) {
			int outputSize = Athena.Cryptography.BlockCiphers [cmacEnum].DefaultBlockSize;

			byte[] functionConfig = Encoding.UTF8.GetBytes (cmacEnum.ToString ());
			return CreateAuthConf(MacFunction.Cmac.ToString(), outputSize / 8, functionConfig);
		}

		/// <summary>
		/// Creates a new authentication configuration using Poly1305-{cipher} construction.
		/// </summary>
		/// <remarks>
		/// The Poly1305 configuration generated may be used with a MacStream, 
		/// e.g. package payload item authentication.
		/// </remarks>
		/// <returns>The authentication configuration as a VerificationFunctionConfiguration.</returns>
		/// <param name="cmacEnum">Cmac enum.</param>
		public static VerificationFunctionConfiguration CreateAuthenticationConfigurationPoly1305(SymmetricBlockCipher cipherEnum = DefaultCmacCipher) {
			int outputSize = Athena.Cryptography.BlockCiphers [cipherEnum].DefaultBlockSize;
			byte[] functionConfig = Encoding.UTF8.GetBytes (cipherEnum.ToString ());
			return CreateAuthConf(MacFunction.Poly1305.ToString(), outputSize / 8, functionConfig);
		}

		private static VerificationFunctionConfiguration CreateAuthConf(string functionName, int outputSize, byte[] functionConfig) {
			var config = new VerificationFunctionConfiguration {
				FunctionType = VerificationFunctionType.Mac.ToString(),
				FunctionName = functionName,
				FunctionConfiguration = functionConfig,
				Salt = new byte[outputSize]
			};
			StratCom.EntropySource.NextBytes(config.Salt);
			return config;
		}
	}
}

