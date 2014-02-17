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
using System.Diagnostics;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyConfirmation
{
	public static class ConfirmationFactory
	{
		/// <summary>
		/// Creates a key confirmation. 
		/// </summary>
		/// <returns>A key confirmation as a verification configuration.</returns>
		/// <param name="key">Key to confirm. Often constitutes key prior to key derivation.</param>
		/// <exception cref="ArgumentException">Key is null or zero-length.</exception>
		public static VerificationFunctionConfiguration GenerateKeyConfirmation (HashFunction hashFEnum, byte[] key, out byte[] verifiedOutput) {
			if (key.IsNullOrZeroLength()) {
				throw new ArgumentException ("Key is null or zero-length.", "key");
			}

			int outputSize;
			var config = AuthenticationConfigurationFactory.CreateAuthenticationConfigurationHmac(hashFEnum, out outputSize);

			var macP = AuthenticatorFactory.CreateHmacPrimitive (hashFEnum, key, config.Salt);

			if (config.AdditionalData != null) 
				macP.BlockUpdate(config.AdditionalData, 0, config.AdditionalData.Length);

			verifiedOutput = new byte[macP.MacSize];
			macP.DoFinal(verifiedOutput, 0);

			Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "CreateDefaultManifestKeyConfirmation", "Verified output", 
				verifiedOutput.ToHexString()));

			return config;
		}
	}
}

