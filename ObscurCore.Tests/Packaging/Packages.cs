using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging
{
    public class Packages
    {

        [Test]
        public void WriteSimpleSymmetricPackage() {
            
            var mCipher = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.HC256);

            var preKey = new byte[mCipher.KeySize / 8];
            StratCom.EntropySource.NextBytes(preKey);

			var manifestCrypto = new SymmetricManifestCryptographyConfiguration() 
			{
				SymmetricCipher = mCipher,
				KeyDerivation = new KeyDerivationConfiguration() {
					SchemeName = KeyDerivationFunctions.Scrypt.ToString(),
					SchemeConfiguration = ScryptConfigurationUtility.Write(ScryptConfigurationUtility.DefaultIterationPower, 
						ScryptConfigurationUtility.DefaultBlocks, ScryptConfigurationUtility.DefaultParallelisation),
                    Salt = new byte[32]
				}
			};
		    StratCom.EntropySource.NextBytes(manifestCrypto.KeyDerivation.Salt);

            var items = Utilities.GetItemsStreamExample(IOTestBase.SmallTextFileList);
            var manifest = new Manifest
                {
                    PayloadItems = items,
                    PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Frameshift)
                };

            IOTestBase.PackageDestinationDirectory.Create();
            var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar +
                "SymmetricPackage" + IOTestBase.PackageExtension, FileMode.Create);
            
            StratCom.WritePackageSymmetric(fs, manifest, manifestCrypto, preKey);

            // We've written the package and closed the stream now
        }
    }
}
