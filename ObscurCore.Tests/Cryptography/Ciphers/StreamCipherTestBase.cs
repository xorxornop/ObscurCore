using ObscurCore.Cryptography;
using NUnit.Framework;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream;

namespace ObscurCore.Tests.Cryptography.Ciphers
{
	public abstract class StreamCipherTestBase : CipherTestBase
    {
		protected StreamCipher Cipher;

		protected StreamCipherTestBase(StreamCipher cipher) 
		{ 
			Cipher = cipher;
		}

		protected override ObscurCore.DTO.CipherConfiguration GetCipherConfiguration (CipherTestCase testCase) {
			var config = CipherConfigurationFactory.CreateStreamCipherConfiguration (Cipher, testCase.Key.Length * 8);
			config.InitialisationVector = testCase.IV;
			return config;
		}

		[Test]
		public void StreamingPerformance () {
			var config = CipherConfigurationFactory.CreateStreamCipherConfiguration(Cipher);
			RunPerformanceTest(config);
		}
    }
}
