using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Packaging.Multiplexing;
using ObscurCore.Tests.Cryptography;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging
{
    public class Packages
    {
        [Test]
        public void SymmetricSimplePackage()
        {
            SymmetricPackageTest("SymmetricSimplePackage", PayloadLayoutScheme.Simple);
        }

        [Test]
        public void SymmetricFrameshiftPackage()
        {
            SymmetricPackageTest("SymmetricFrameshiftPackage", PayloadLayoutScheme.Frameshift);
        }
#if INCLUDE_FABRIC
		[Test]
		public void SymmetricFabricPackage() {
			SymmetricPackageTest("SymmetricFabricPackage", PayloadLayoutScheme.Fabric);
		}
#endif
        private static void SymmetricPackageTest(string testName, PayloadLayoutScheme scheme)
        {
            // Process of writing destroys preKey variable passed in for security
            // We must copy it to a local variable before reading the package back
            var preKey = KeyProviders.Alice.SymmetricKeys.ElementAt(
                StratCom.EntropySupplier.Next(KeyProviders.Alice.SymmetricKeys.Count()));

            var totalLen = IOTestBase.LargeBinaryFileList.Sum(file => file.Length);
            int expLen = (int)(totalLen * 1.1);

            TimeSpan enc, dec;
            using (var ms = new MemoryStream(expLen)) {
                var sw = Stopwatch.StartNew();
                var package = new PackageWriter(preKey, lowEntropy: false, layoutScheme: scheme); // low entropy = false
                foreach (var file in IOTestBase.LargeBinaryFileList) {
                    package.AddFile(file.FullName);
                }
                package.Write(ms, false);
                sw.Stop();
                enc = sw.Elapsed;
                sw.Reset();
                ms.Seek(0, SeekOrigin.Begin);
                using (var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar
                    + testName + IOTestBase.PackageExtension, FileMode.Create)) {
                    ms.CopyTo(fs);
                }
                ms.Seek(0, SeekOrigin.Begin);
                sw.Start();
                // Now read it back
                var readingPackage = PackageReader.FromStream(ms, KeyProviders.Alice);
                readingPackage.ReadToDirectory(IOTestBase.PackageDestinationDirectory.FullName, true);
                sw.Stop();
                dec = sw.Elapsed;
            }

            var megabytes = (double)totalLen / 1024 / 1024;
            Assert.Pass("{0} ms / {1:N2} MB/s -> {2} ms / {3:N2} MB/s.", enc.Milliseconds, (1000.0 / (double)enc.Milliseconds) * megabytes,
                dec.Milliseconds, (1000.0 / (double)dec.Milliseconds) * megabytes);
        }

        // EC-UM1

        [Test]
        public void UM1SimplePackage()
        {
            UM1PackageTest("UM1SimplePackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Simple);
        }

        [Test]
        public void UM1FrameshiftPackage()
        {
            UM1PackageTest("UM1FrameshiftPackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Frameshift);
        }

        [Test]
        public void UM1FrameshiftSmallPackage()
        {
            UM1PackageTest("UM1FrameshiftSmallPackage", IOTestBase.SmallTextFileList, PayloadLayoutScheme.Frameshift);
        }

        [Test]
        public void UM1FrameshiftSmallPackagePrecomputedPayload()
        {
            UM1PackageTest("UM1FrameshiftSmallPackage", IOTestBase.SmallTextFileList, PayloadLayoutScheme.Frameshift, true);
        }

#if INCLUDE_FABRIC
		[Test]
		public void UM1FabricPackage() {
            UM1PackageTest("UM1FabricPackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Fabric);
		}
#endif
        [Test]
        public void UM1FrameshiftDirectoryPackage()
        {
            UM1PackageTest("UM1FrameshiftDirectoryPackage", IOTestBase.LargeBinaryFilesSourceDirectory, PayloadLayoutScheme.Frameshift);
        }
        private static void UM1PackageTest(string testName, List<FileInfo> data, PayloadLayoutScheme scheme, bool precomputed = false)
        {
            // Process of writing destroys sender and receiver key variables passed in for security
            // We must copy it to a local variable before reading the package back
            int senderKeyIndex = StratCom.EntropySupplier.Next(KeyProviders.Alice.EcKeypairs.Count());
            var senderKeyEnumerated = KeyProviders.Alice.EcKeypairs.ElementAt(senderKeyIndex);
            var receiverKeyEnumerated = KeyProviders.Bob.EcKeypairs.First(
                keypair => keypair.CurveName.Equals(senderKeyEnumerated.CurveName));

            var totalLen = data.Sum(file => file.Length);
            int expLen = (int)(totalLen * 1.1);

            TimeSpan enc, dec;
            using (var ms = new MemoryStream(expLen)) {
                var sw = Stopwatch.StartNew();
                var packageWriter = new PackageWriter(senderKeyEnumerated, receiverKeyEnumerated, scheme);

                foreach (var file in data) {
                    packageWriter.AddFile(file.FullName);
                }

                if (scheme == PayloadLayoutScheme.Frameshift && precomputed) {
                    packageWriter.SetPayloadConfiguration(PayloadLayoutConfigurationFactory.CreateFrameshiftPrecomputedVariable(data.Count));
                }

                packageWriter.Write(ms, false);
                sw.Stop();
                enc = sw.Elapsed;
                sw.Reset();
                ms.Seek(0, SeekOrigin.Begin);
                using (var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar
                    + testName + IOTestBase.PackageExtension, FileMode.Create)) {
                    ms.CopyTo(fs);
                }
                ms.Seek(0, SeekOrigin.Begin);
                sw.Start();
                // Now read it back
                var packageReader = PackageReader.FromStream(ms, KeyProviders.Bob);
                packageReader.ReadToDirectory(IOTestBase.PackageDestinationDirectory.FullName, true);
                sw.Stop();
                dec = sw.Elapsed;
            }

            var megabytes = (double)totalLen / 1024 / 1024;
            Assert.Pass("{0} ms / {1:N2} MB/s -> {2} ms / {3:N2} MB/s. Used curve {4}", enc.Milliseconds, (1000.0 / (double)enc.Milliseconds) * megabytes,
                dec.Milliseconds, (1000.0 / (double)dec.Milliseconds) * megabytes, senderKeyEnumerated.CurveName);
        }
        private static void UM1PackageTest(string testName, DirectoryInfo dir, PayloadLayoutScheme scheme)
        {
            // Process of writing destroys sender and receiver key variables passed in for security
            // We must copy it to a local variable before reading the package back
            var senderKeyEnumerated = KeyProviders.Alice.EcKeypairs.ElementAt(
                StratCom.EntropySupplier.Next(KeyProviders.Alice.EcKeypairs.Count()));
            var receiverKeyEnumerated = KeyProviders.Bob.EcKeypairs.First(
                keypair => keypair.CurveName.Equals(senderKeyEnumerated.CurveName));

            var files = dir.EnumerateFiles("*", SearchOption.AllDirectories);
            var totalLen = files.Sum(file => file.Length);
            int expLen = (int)(totalLen * 1.1);

            TimeSpan enc, dec;
            using (var ms = new MemoryStream(expLen)) {
                var sw = Stopwatch.StartNew();
                var packageWriter = new PackageWriter(senderKeyEnumerated, receiverKeyEnumerated, scheme);
                packageWriter.AddDirectory(dir.FullName, SearchOption.AllDirectories);
                packageWriter.Write(ms, false);
                sw.Stop();
                enc = sw.Elapsed;
                sw.Reset();
                ms.Seek(0, SeekOrigin.Begin);
                using (var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar
                    + testName + IOTestBase.PackageExtension, FileMode.Create)) {
                    ms.CopyTo(fs);
                }
                ms.Seek(0, SeekOrigin.Begin);
                sw.Start();
                // Now read it back
                var packageReader = PackageReader.FromStream(ms, KeyProviders.Bob);
                packageReader.ReadToDirectory(IOTestBase.PackageDestinationDirectory.FullName, true);
                sw.Stop();
                dec = sw.Elapsed;
            }

            var megabytes = (double)totalLen / 1024 / 1024;
            Assert.Pass("{0} ms / {1:N2} MB/s -> {2} ms / {3:N2} MB/s. Used curve {4}", enc.Milliseconds, (1000.0 / (double)enc.Milliseconds) * megabytes,
                dec.Milliseconds, (1000.0 / (double)dec.Milliseconds) * megabytes, senderKeyEnumerated.CurveName);
        }
    }
}
