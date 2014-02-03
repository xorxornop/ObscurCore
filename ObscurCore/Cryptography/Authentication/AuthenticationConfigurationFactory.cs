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
		const HashFunction DefaultHmacFunction = HashFunction.Blake2B256;
		const SymmetricBlockCipher DefaultCmacCipher = SymmetricBlockCipher.Aes;
		const SymmetricBlockCipher DefaultPoly1305BlockCipher = SymmetricBlockCipher.Aes;

		/// <summary>
		/// Creates a new authentication configuration. 
		/// HMAC or CMAC/OMAC1 selection will use default basis primitives (BLAKE2B256 or AES, respectively).
		/// </summary>
		/// <remarks>
		/// The MAC configuration generated may be used with a MacStream, 
		/// e.g. package payload item authentication.
		/// </remarks>
		/// <returns>The authentication configuration as a VerificationFunctionConfiguration.</returns>
		/// <param name="macFEnum">MAC function.</param>
		/// <param name="outputSize">Size of the output from the function in bytes.</param>
		public static VerificationFunctionConfiguration CreateAuthenticationConfiguration(MacFunction macFEnum, out int outputSize) {
			if (!Athena.Cryptography.MacFunctions [macFEnum].OutputSize.HasValue) {
				// Either HMAC or CMAC/OMAC1 is being used.
				switch (macFEnum) {
				case MacFunction.Hmac:
					return CreateAuthenticationConfigurationHmac (DefaultHmacFunction, out outputSize);
				case MacFunction.Cmac:
					return CreateAuthenticationConfigurationCmac (DefaultCmacCipher, out outputSize);
				default:
					throw new NotImplementedException ();
				}
			}

			if (macFEnum == MacFunction.Poly1305) {
				outputSize = 16;
				return CreateAuthenticationConfigurationPoly1305 (DefaultPoly1305BlockCipher);
			}
				
			outputSize = Athena.Cryptography.MacFunctions [macFEnum].OutputSize.Value / 8;
			int outputSizeBits = outputSize * 8;

			return CreateAuthConf (macFEnum.ToString (), outputSizeBits, outputSizeBits, null, null);
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
		public static VerificationFunctionConfiguration CreateAuthenticationConfigurationHmac (HashFunction hmacEnum, 
			out int outputSize, int? keySize = null) 
		{
			outputSize = Athena.Cryptography.HashFunctions[hmacEnum].OutputSize;
			byte[] functionConfig = Encoding.UTF8.GetBytes (hmacEnum.ToString ());
			return CreateAuthConf(MacFunction.Hmac.ToString(), keySize ?? outputSize, outputSize, functionConfig, null);
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
		public static VerificationFunctionConfiguration CreateAuthenticationConfigurationCmac(SymmetricBlockCipher cmacEnum, out int outputSize) {
			outputSize = Athena.Cryptography.BlockCiphers[cmacEnum].DefaultBlockSize;
			int keySize = Athena.Cryptography.BlockCiphers[cmacEnum].DefaultKeySize;
			byte[] functionConfig = Encoding.UTF8.GetBytes (cmacEnum.ToString());

			return CreateAuthConf(MacFunction.Cmac.ToString(), keySize, outputSize, functionConfig, null);
		}

		/// <summary>
		/// Creates a new authentication configuration using Poly1305-{block cipher} construction, 
		/// such as Poly1305-AES.
		/// </summary>
		/// <remarks>
		/// The Poly1305 configuration generated may be used with a MacStream, 
		/// e.g. package payload item authentication.
		/// </remarks>
		/// <returns>The authentication configuration as a VerificationFunctionConfiguration.</returns>
		/// <param name="cmacEnum">Cmac enum.</param>
		public static VerificationFunctionConfiguration CreateAuthenticationConfigurationPoly1305(SymmetricBlockCipher cipherEnum, byte[] nonce = null) {
			if (Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize != 128) {
				throw new ArgumentException ("Incompatible cipher block size.");
			}

			byte[] functionConfig = Encoding.UTF8.GetBytes (cipherEnum.ToString ());

			if (nonce == null) {
				nonce = new byte[16];
				StratCom.EntropySource.NextBytes (nonce);
			}

			return CreateAuthConf(MacFunction.Poly1305.ToString(), 256, 128, functionConfig, nonce);
		}

		private static VerificationFunctionConfiguration CreateAuthConf(string functionName, int keySizeBits, int outputSizeBits, byte[] functionConfig, byte[] nonce) {
			var config = new VerificationFunctionConfiguration {
				FunctionType = VerificationFunctionType.Mac.ToString(),
				FunctionName = functionName,
				FunctionConfiguration = functionConfig,
				KeySizeBits = keySizeBits,
				Nonce = nonce,
				Salt = new byte[keySizeBits / 8]
			};
			StratCom.EntropySource.NextBytes(config.Salt);
			return config;
		}
	}
}
