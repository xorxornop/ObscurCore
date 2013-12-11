using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;
using ObscurCore.Cryptography;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging.Serialisation
{
	class ManifestTests : SerialisationTestBase
	{
		[Test]
		public void Test() {

			var manifest = new Manifest
			    {
                    PayloadItems = new List<PayloadItem>(),
                    
			        PayloadOffset = 69,
			        PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Fabric)
			    };

            manifest.PayloadItems.Add(new PayloadItem() { Encryption = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration
                                (SymmetricBlockCipher.AES, BlockCipherModes.CTR, BlockCipherPaddings.None) });

		    var stream = StratCom.SerialiseDto(manifest);
            stream.Seek(0, SeekOrigin.Begin);
		    var outputObj = StratCom.DeserialiseDTO<Manifest>(stream.ToArray());

            bool equal = manifest.Equals(outputObj);

            Assert.IsTrue(equal);

		}
	}
}

