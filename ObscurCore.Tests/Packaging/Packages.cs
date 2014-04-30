using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Tests.Cryptography;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging
{
    public class Packages
    {
		[Test]
		public void SymmetricSimplePackage() {
			SymmetricPackageTest ("SymmetricSimplePackage", PayloadLayoutScheme.Simple);
		}

		[Test]
		public void SymmetricFrameshiftPackage() {
			SymmetricPackageTest ("SymmetricFrameshiftPackage", PayloadLayoutScheme.Frameshift);
		}
#if INCLUDE_FABRIC
		[Test]
		public void SymmetricFabricPackage() {
			SymmetricPackageTest ("SymmetricFabricPackage", PayloadLayoutScheme.Fabric);
		}
#endif
		private static void SymmetricPackageTest(string testName, PayloadLayoutScheme scheme) {
			// Process of writing destroys preKey variable passed in for security
			// We must copy it to a local variable before reading the package back
			var preKeyEnumerated = KeyProviders.Alice.SymmetricKeys.First();
			var preKey = new byte[preKeyEnumerated.Length];
			Array.Copy(preKeyEnumerated, preKey, preKey.Length);

			TimeSpan enc, dec;
			using (var ms = new MemoryStream ()) {
				var sw = Stopwatch.StartNew ();
				var package = new PackageWriter (preKey, true, scheme); // low entropy = false
				foreach (var file in IOTestBase.LargeBinaryFileList) {
					package.AddFile (file.FullName);
				}
				package.Write (ms, false);
				sw.Stop ();
				enc = sw.Elapsed;
				sw.Reset ();
				ms.Seek (0, SeekOrigin.Begin);
				using(var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar 
					+ testName + IOTestBase.PackageExtension, FileMode.Create)) {
					ms.CopyTo (fs);
				}
				ms.Seek (0, SeekOrigin.Begin);
				sw.Start ();
				// Now read it back
				var readingPackage = PackageReader.FromStream (ms, KeyProviders.Alice);
				readingPackage.ReadToDirectory (IOTestBase.PackageDestinationDirectory.FullName);
				sw.Stop ();
				dec = sw.Elapsed;
			}

			Assert.Pass ("Packaging: {0} ms.\nDepackaging: {1} ms.", enc.Milliseconds, dec.Milliseconds);
		}

		// EC-UM1

		[Test]
		public void UM1SimplePackage() {
			UM1PackageTest ("UM1SimplePackage", PayloadLayoutScheme.Simple);
		}

		[Test]
		public void UM1FrameshiftPackage() {
			UM1PackageTest ("UM1FrameshiftPackage", PayloadLayoutScheme.Frameshift);
		}
#if INCLUDE_FABRIC
		[Test]
		public void UM1FabricPackage() {
			UM1PackageTest ("UM1FabricPackage", PayloadLayoutScheme.Fabric);
		}
#endif
		private static void UM1PackageTest(string testName, PayloadLayoutScheme scheme) {
			// Process of writing destroys sender and receiver key variables passed in for security
			// We must copy it to a local variable before reading the package back
			var senderKeyEnumerated = KeyProviders.Alice.EcKeypairs.ElementAt (StratCom.EntropySupplier.Next (KeyProviders.Alice.EcKeypairs.Count ()));
			var receiverKeyEnumerated = KeyProviders.Bob.EcKeypairs.First ((keypair) => keypair.CurveName.Equals (senderKeyEnumerated.CurveName));

			TimeSpan enc, dec;
			using (var ms = new MemoryStream ()) {
				var sw = Stopwatch.StartNew ();
				var packageWriter = new PackageWriter (senderKeyEnumerated, receiverKeyEnumerated, scheme);
				foreach (var file in IOTestBase.LargeBinaryFileList) {
					packageWriter.AddFile (file.FullName);
				}
				packageWriter.Write (ms, false);
				sw.Stop ();
				enc = sw.Elapsed;
				sw.Reset ();
				ms.Seek (0, SeekOrigin.Begin);
				using(var fs = new FileStream(IOTestBase.PackageDestinationDirectory.FullName + Path.DirectorySeparatorChar 
					+ testName + IOTestBase.PackageExtension, FileMode.Create)) {
					ms.CopyTo (fs);
				}
				ms.Seek (0, SeekOrigin.Begin);
				sw.Start ();
				// Now read it back
				var packageReader = PackageReader.FromStream (ms, KeyProviders.Bob);
				packageReader.ReadToDirectory (IOTestBase.PackageDestinationDirectory.FullName);
				sw.Stop ();
				dec = sw.Elapsed;
			}

			Assert.Pass ("Packaging: {0} ms.\nDepackaging: {1} ms.\nUsed curve: {2}", enc.Milliseconds, dec.Milliseconds, senderKeyEnumerated.CurveName);
		}
    }
}
