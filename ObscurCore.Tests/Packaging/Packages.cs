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

            var items = Utilities.GetItemsStreamExample(IOTestBase.SmallTextFileList);
            var manifest = new Manifest
                {
                    PayloadItems = items,
                    PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Frameshift)
                };

            IOTestBase.PackageDestinationDirectory.Create();
            using (var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + 
                Path.DirectorySeparatorChar + "SymmetricPackage" + IOTestBase.PackageExtension, FileMode.Create)) 
            {
                StratCom.WritePackageSymmetric(fs, manifest, mCipher, preKey);
            }


            // We've written the package and closed the stream now
        }


        [Test]
        public void RoundTripSimpleSymmetricPackage() {
            var mCipher = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.HC256);

            var preKey = new byte[mCipher.KeySize / 8];
            StratCom.EntropySource.NextBytes(preKey);

            var items = Utilities.GetItemsStreamExample(IOTestBase.SmallTextFileList);
            var manifest = new Manifest
                {
                    PayloadItems = items,
                    PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Frameshift)
                };

            using (var ms = new MemoryStream()) 
            {
                StratCom.WritePackageSymmetric(ms, manifest, mCipher, preKey);

                ms.Seek(0, SeekOrigin.Begin);

                IManifestCryptographySchemeConfiguration mCryptoConfig;
                ManifestCryptographySchemes scheme;
                int offset;
                //var header = StratCom.ReadPackageManifestHeader(ms, out mCryptoConfig, out scheme, out offset);

                var symKey = new List<byte[]> {preKey};

                var readManifest = StratCom.ReadPackageManifest(ms, symKey, null, null, null, null, out offset);

            }

            
        }
    }
}
