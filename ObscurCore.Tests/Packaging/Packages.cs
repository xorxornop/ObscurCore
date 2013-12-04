using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging
{
    public class Packages
    {
        private readonly KeyProvider _provider = new KeyProvider();

        //[Test]
        //public void WriteSimpleSymmetricPackage() {
            
        //    var mCipher = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCipher.Hc256);

        //    var preKey = new byte[mCipher.KeySizeBits / 8];
        //    StratCom.EntropySource.NextBytes(preKey);

        //    var items = Utilities.GetItemsStreamExample(IOTestBase.SmallTextFileList);
        //    var manifest = new Manifest
        //        {
        //            PayloadItems = items,
        //            PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutScheme.Frameshift)
        //        };

        //    if(!IOTestBase.PackageDestinationDirectory.Exists) IOTestBase.PackageDestinationDirectory.Create();
        //    using (var temp = new MemoryStream()) {
        //        using (var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar + 
        //            "SymmetricPackage" + IOTestBase.PackageExtension, FileMode.Create)) 
        //        {
        //            PackageWriter.WritePackageSymmetric(fs, temp, manifest, mCipher, preKey);
        //        }
        //    }
        //    // We've written the package and closed the stream now
        //}


        [Test]
        public void RoundTripSimpleSymmetricPackage() {

            var preKey = new byte[_provider.SymmetricKeys.First().Length];
            Array.Copy(_provider.SymmetricKeys.First(), preKey, preKey.Length);

            var preKeyBackup = new byte[preKey.Length]; // we have to save the key from the security procedure of clearing it!
            Array.Copy(preKey, preKeyBackup,preKey.Length);

            using (var ms = new MemoryStream()) {
                Debug.Print("\nSTARTING PACKAGE WRITE SECTION OF UNIT TEST\n");

                var package = new Package(preKey);
                foreach (var file in IOTestBase.SmallTextFileList) {
                    package.AddFile(file.FullName);
                }
                package.Write(ms, false);
                
                ms.Seek(0, SeekOrigin.Begin);

                Debug.Print("\nSTARTING PACKAGE READ SECTION OF UNIT TEST\n");

                var readingPackage = Package.FromStream(ms, _provider);
                readingPackage.ReadToDirectory(IOTestBase.SmallTextFilesDestinationDirectory.FullName);

            }
        }
    }
}
