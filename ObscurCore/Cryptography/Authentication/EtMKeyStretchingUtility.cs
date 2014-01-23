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
using System.Text;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Authentication
{
	public static class EtMKeyStretchingUtility
	{
		public static void DeriveWorkingKeys (byte[] preKey, int cipherKeySize, VerificationFunctionConfiguration authConfig, 
			KeyDerivationConfiguration kdfConfig, out byte[] encryptionKey, out byte[] authenticationKey)
		{
			int authKeySize;
			MacFunction manifestAuthFunction = authConfig.FunctionName.ToEnum<MacFunction> ();
			switch (manifestAuthFunction) {
			case MacFunction.Hmac:
				HashFunction hmacFEnum = 
					Encoding.UTF8.GetString (authConfig.FunctionConfiguration).ToEnum<HashFunction> ();
				authKeySize = Athena.Cryptography.HashFunctions [hmacFEnum].OutputSize / 8;
				break;
			case MacFunction.Cmac:
				SymmetricBlockCipher cmacFEnum = 
					Encoding.UTF8.GetString (authConfig.FunctionConfiguration).ToEnum<SymmetricBlockCipher> ();
				authKeySize = Athena.Cryptography.BlockCiphers [cmacFEnum].DefaultBlockSize / 8;
				break;
			default:
				authKeySize = Athena.Cryptography.MacFunctions[manifestAuthFunction].OutputSize.Value / 8;
				break;
			}

			// Derive the key which will be used for encrypting the manifest
			byte[] stretchedWorkingMKeys = Source.DeriveKeyWithKdf(kdfConfig.SchemeName.ToEnum<KeyDerivationFunction>(),
				preKey, kdfConfig.Salt, cipherKeySize + authKeySize,
				kdfConfig.SchemeConfiguration);

			// Retrieve the working encryption & authentication subkeys from the stretched manifest key
			encryptionKey = new byte[cipherKeySize];
			authenticationKey = new byte[authKeySize];
			Array.Copy (stretchedWorkingMKeys, 0, encryptionKey, 0, cipherKeySize);
			Array.Copy (stretchedWorkingMKeys, cipherKeySize, authenticationKey, 0, authKeySize);

			// Clear the pre-key and stretched manifest working combination key from memory
			Array.Clear(preKey, 0, preKey.Length);
			Array.Clear(stretchedWorkingMKeys, 0, stretchedWorkingMKeys.Length);
		}
	}
}

