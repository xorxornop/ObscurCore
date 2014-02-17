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
using System.Collections.Generic;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy
{
	/// <summary>
	/// Instantiator for CSPRNGs.
	/// </summary>
	public static class CsprngFactory
	{
		private readonly static IDictionary<CsPseudorandomNumberGenerator, Func<byte[], Csprng>> PrngInstantiators =
			new Dictionary<CsPseudorandomNumberGenerator, Func<byte[], Csprng>>();

		/// <summary>
		/// Instantiates and returns a CSPRNG function.
		/// </summary>
		/// <param name="csprngEnum">Underlying function to use.</param>
		/// <param name="config">Serialised configuration of the CSPRNG.</param>
		public static Csprng CreateCsprng (CsPseudorandomNumberGenerator csprngEnum, byte[] config) {
			return PrngInstantiators[csprngEnum](config);
		}

		public static Csprng CreateCsprng (string csprngName, byte[] config) {
			return CreateCsprng(csprngName.ToEnum<CsPseudorandomNumberGenerator>(), config);
		}

		public static StreamCipherCsprngConfiguration CreateStreamCipherCsprngConfiguration
			(CsPseudorandomNumberGenerator cipherEnum)
		{
			return StreamCsprng.CreateRandomConfiguration(cipherEnum);
		}

		static CsprngFactory ()
		{
			PrngInstantiators.Add(CsPseudorandomNumberGenerator.Salsa20, config => new Salsa20Generator(config));
			PrngInstantiators.Add(CsPseudorandomNumberGenerator.Sosemanuk, config => new SosemanukGenerator(config));
		}
	}
}

