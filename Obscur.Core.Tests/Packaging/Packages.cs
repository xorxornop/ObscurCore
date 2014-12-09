using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using NUnit.Framework;
using Obscur.Core.Packaging;
using Obscur.Core.Packaging.Multiplexing;
using Obscur.Core.Tests.Cryptography;

namespace Obscur.Core.Tests.Packaging
{
    public class Packages
    {
        [Test]
        public void SymmetricSimplePackage()
        {
            SymmetricPackageTest("SymmetricSimplePackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Simple, false);
        }

        [Test]
        public void SymmetricFrameshiftPackage()
        {
            SymmetricPackageTest("SymmetricFrameshiftPackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Frameshift, false);
        }
#if INCLUDE_FABRIC
		[Test]
		public void SymmetricFabricPackage() {
            SymmetricPackageTest("SymmetricFabricPackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Fabric, false);
		}
#endif
        private static void SymmetricPackageTest(string testName, List<FileInfo> data, PayloadLayoutScheme scheme, bool outputToFile = false, bool precomputed = false)
        {
            // Process of writing destroys preKey variable passed in for security
            // We must copy it to a local variable before reading the package back
            var preKey = KeyProviders.Alice.SymmetricKeys.ElementAt(
                StratCom.EntropySupplier.Next(KeyProviders.Alice.SymmetricKeys.Count()));

            var totalLen = data.Sum(file => file.Length);
            int expLen = (int)(totalLen * 1.1);

            TimeSpan enc, dec;
            using (var ms = new MemoryStream(expLen)) {
                var sw = Stopwatch.StartNew();
                var packageWriter = new PackageWriter(preKey, lowEntropy: false, layoutScheme: scheme); // low entropy = false

                foreach (var file in data) {
                    packageWriter.AddFile(file.FullName);
                }

                if (precomputed) {
                    if (scheme == PayloadLayoutScheme.Simple) {
                        packageWriter.SetPayloadConfiguration(PayloadLayoutConfigurationFactory.CreateSimplePreallocated(data.Count));
                    } else if (scheme == PayloadLayoutScheme.Frameshift) {
                        packageWriter.SetPayloadConfiguration(
                            PayloadLayoutConfigurationFactory.CreateFrameshiftPrecomputedVariable(data.Count));
                    } else {
                        throw new InvalidOperationException();
                    }
                }

                packageWriter.Write(ms, false);
                sw.Stop();
                enc = sw.Elapsed;
                sw.Reset();
                ms.Seek(0, SeekOrigin.Begin);
                if (outputToFile) {
                    using (var fs = new FileStream(
                        IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar + testName +
                        IOTestBase.PackageExtension, FileMode.Create)) {
                        ms.CopyTo(fs);
                    }
                    ms.Seek(0, SeekOrigin.Begin);
                }
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
            UM1PackageTest("UM1SimplePackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Simple, false);
        }

        [Test]
        public void UM1FrameshiftPackage()
        {
            UM1PackageTest("UM1FrameshiftPackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Frameshift, false);
        }

        [Test]
        public void UM1FrameshiftSmallPackage()
        {
            UM1PackageTest("UM1FrameshiftSmallPackage", IOTestBase.SmallTextFileList, PayloadLayoutScheme.Frameshift, false);
        }

        [Test]
        public void UM1FrameshiftSmallPackagePrecomputedPayload()
        {
            UM1PackageTest("UM1FrameshiftSmallPackage", IOTestBase.SmallTextFileList, PayloadLayoutScheme.Frameshift, false, true);
        }

        [Test]
        public void UM1FrameshiftDirectoryPackage()
        {
            UM1PackageTest("UM1FrameshiftDirectoryPackage", IOTestBase.LargeBinaryFilesSourceDirectory.EnumerateFiles("*", SearchOption.AllDirectories).ToList(), PayloadLayoutScheme.Frameshift, false);
        }

#if INCLUDE_FABRIC
		[Test]
		public void UM1FabricPackage() {
            UM1PackageTest("UM1FabricPackage", IOTestBase.LargeBinaryFileList, PayloadLayoutScheme.Fabric, false);
		}

        [Test]
        public void UM1FabricSmallPackage()
        {
            UM1PackageTest("UM1FabricSmallPackage", IOTestBase.SmallTextFileList, PayloadLayoutScheme.Fabric, false);
        }
#endif      

        private static void UM1PackageTest(string testName, List<FileInfo> data, PayloadLayoutScheme scheme, bool outputToFile = false, bool precomputed = false)
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

                if (precomputed) {
                    if (scheme == PayloadLayoutScheme.Simple) {
                        packageWriter.SetPayloadConfiguration(PayloadLayoutConfigurationFactory.CreateSimplePreallocated(data.Count));
                    } else if (scheme == PayloadLayoutScheme.Frameshift) {
                        packageWriter.SetPayloadConfiguration(
                            PayloadLayoutConfigurationFactory.CreateFrameshiftPrecomputedVariable(data.Count));
                    } else {
                        throw new InvalidOperationException();
                    }          
                }

                packageWriter.Write(ms, false);
                sw.Stop();
                enc = sw.Elapsed;
                sw.Reset();
                ms.Seek(0, SeekOrigin.Begin);
                if (outputToFile) {
                    using (var fs = new FileStream(
                        IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar + testName +
                        IOTestBase.PackageExtension, FileMode.Create)) {
                        ms.CopyTo(fs);
                    }
                    ms.Seek(0, SeekOrigin.Begin);
                }
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
