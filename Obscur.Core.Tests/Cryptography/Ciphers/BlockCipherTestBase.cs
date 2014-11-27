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
using NUnit.Framework;
using Obscur.Core;
using Obscur.Core.Cryptography.Ciphers;
using Obscur.Core.Cryptography.Ciphers.Block;
using Obscur.Core.DTO;

namespace ObscurCore.Tests.Cryptography.Ciphers
{
	internal abstract class BlockCipherTestBase : CipherTestBase
	{
		protected BlockCipher Cipher;

		protected BlockCipherTestBase(BlockCipher cipher) 
		{ 
			Cipher = cipher;
		}

		protected override CipherConfiguration GetCipherConfiguration (CipherTestCase testCase) {
			if (String.IsNullOrEmpty(testCase.Extra)) {
				throw new InvalidOperationException ("Block cipher test cases require block & padding information (extra is null/empty).");
			}

			var extraDataSplit = testCase.Extra.Split (new[]{ '/' }, StringSplitOptions.None);
			if (extraDataSplit.Length != 2) {
				throw new InvalidOperationException ("Block cipher test cases require block & padding information.");
			}

			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration (Cipher,
				extraDataSplit[0].ToEnum<BlockCipherMode>(), extraDataSplit[1].ToEnum<BlockCipherPadding>(), 
				testCase.Key.Length * 8);

			config.InitialisationVector = testCase.IV;
			return config;
		}

		#region Paddingless modes of operation
		[Test]
		public virtual void StreamingPerformance_CTR () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Ctr,
				BlockCipherPadding.None);
			RunPerformanceTest(config);
		}

		[Test]
		public virtual void StreamingPerformance_CFB () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Cfb,
				BlockCipherPadding.None);
			RunPerformanceTest(config);
		}

		[Test]
		public virtual void StreamingPerformance_OFB () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Ofb,
				BlockCipherPadding.None);
			RunPerformanceTest(config);
		}
		#endregion

		#region CBC with padding modes
		[Test]
		public virtual void StreamingPerformance_CBC_ISO10126D2 () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Cbc,
				BlockCipherPadding.Iso10126D2);
			RunPerformanceTest(config);
		}

		[Test]
		public virtual void StreamingPerformance_CBC_ISO7816D4 () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Cbc,
				BlockCipherPadding.Iso7816D4);
			RunPerformanceTest(config);
		}

		[Test]
		public virtual void StreamingPerformance_CBC_PKCS7 () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Cbc,
				BlockCipherPadding.Pkcs7);
			RunPerformanceTest(config);
		}

		[Test]
		public virtual void StreamingPerformance_CBC_TBC () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Cbc,
				BlockCipherPadding.Tbc);
			RunPerformanceTest(config);
		}

		[Test]
		public virtual void StreamingPerformance_CBC_X923 () {
			// Using default block & key size
			var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(Cipher, BlockCipherMode.Cbc,
				BlockCipherPadding.X923);
			RunPerformanceTest(config);
		}
		#endregion
	}
}

