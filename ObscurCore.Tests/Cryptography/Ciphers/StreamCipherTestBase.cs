using ObscurCore.DTO;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream;
using NUnit.Framework;

namespace ObscurCore.Tests.Cryptography.Ciphers
{
    internal abstract class StreamCipherTestBase : CipherTestBase
    {
		protected StreamCipher Cipher;

		protected StreamCipherTestBase(StreamCipher cipher) 
		{ 
			Cipher = cipher;
		}

		protected override CipherConfiguration GetCipherConfiguration (CipherTestCase testCase) {
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
