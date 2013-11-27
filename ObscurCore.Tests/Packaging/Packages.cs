using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging
{
    public class Packages
    {

        [Test]
        public void WriteSimpleSymmetricPackage() {
            
            var mCipher = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Hc256);

            var preKey = new byte[mCipher.KeySize / 8];
            StratCom.EntropySource.NextBytes(preKey);

            var items = Utilities.GetItemsStreamExample(IOTestBase.SmallTextFileList);
            var manifest = new Manifest
                {
                    PayloadItems = items,
                    PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Frameshift)
                };

            if(!IOTestBase.PackageDestinationDirectory.Exists) IOTestBase.PackageDestinationDirectory.Create();
            using (var temp = new MemoryStream()) {
                using (var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar + 
                    "SymmetricPackage" + IOTestBase.PackageExtension, FileMode.Create)) 
                {
                    PackageWriter.WritePackageSymmetric(fs, temp, manifest, mCipher, preKey);
                }
            }
            // We've written the package and closed the stream now
        }


        [Test]
        public void RoundTripSimpleSymmetricPackage() {
            var mCipher = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Hc256);

            var preKey = new byte[mCipher.KeySize / 8];
            StratCom.EntropySource.NextBytes(preKey);

            var preKeyBackup = new byte[preKey.Length]; // we have to save the key from the security procedure of clearing it!
            Array.Copy(preKey, preKeyBackup,preKey.Length);

            var items = Utilities.GetItemsStreamExample(IOTestBase.SmallTextFileList);
            var manifest = new Manifest
                {
                    PayloadItems = items,
                    PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Simple)
                };

            using (var ms = new MemoryStream()) {
                Debug.Print("\nSTARTING PACKAGE WRITE SECTION OF UNIT TEST\n");
                using (var temp = new MemoryStream()) {
                    PackageWriter.WritePackageSymmetric(ms, temp, manifest, mCipher, preKey);
                }
                ms.Seek(0, SeekOrigin.Begin);
                int offset;
                var symKey = new List<byte[]> {preKeyBackup};

                Debug.Print("\nSTARTING PACKAGE READ SECTION OF UNIT TEST\n");

                var readManifest = PackageReader.ReadPackageManifest(ms, symKey, null, null, null, null);

                var path = IOTestBase.SmallTextFilesDestinationDirectory.FullName + Path.DirectorySeparatorChar;

                foreach (var item in readManifest.PayloadItems) {
                    var relativePath = item.RelativePath.Insert(0, path).Replace('/', Path.DirectorySeparatorChar);
                    item.SetStreamBinding(() => new FileStream(relativePath, FileMode.Create));
                }

                PackageReader.ReadPackagePayload(ms, readManifest, null);

            }
        }
    }
}
