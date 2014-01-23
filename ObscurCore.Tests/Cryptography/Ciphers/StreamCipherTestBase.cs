using ObscurCore.Cryptography;
using NUnit.Framework;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream;

namespace ObscurCore.Tests.Cryptography.Ciphers
{
	public abstract class StreamCipherTestBase : CipherTestBase
    {
		protected SymmetricStreamCipher Cipher;

		protected StreamCipherTestBase(SymmetricStreamCipher cipher) 
		{ 
			Cipher = cipher;
		}

		protected override ObscurCore.DTO.SymmetricCipherConfiguration GetCipherConfiguration (CipherTestCase testCase) {
			var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration (Cipher, testCase.Key.Length * 8);
			config.IV = testCase.IV;
			return config;
		}

		[Test]
		public void StreamingPerformance () {
			var config = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(Cipher);
			RunPerformanceTest(config);
		}
    }
}
