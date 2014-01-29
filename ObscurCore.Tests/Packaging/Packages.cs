using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Tests.Cryptography;

namespace ObscurCore.Tests.Packaging
{
    public class Packages
    {
		[Test]
		public void SymmetricSimplePackage() {
			SymmetricPackageTest ("SymmetricSimplePackage", ObscurCore.Packaging.PayloadLayoutScheme.Simple);
		}

		[Test]
		public void SymmetricFrameshiftPackage() {
			SymmetricPackageTest ("SymmetricFrameshiftPackage", ObscurCore.Packaging.PayloadLayoutScheme.Frameshift);
		}

		#if INCLUDE_FABRIC
		[Test]
		public void SymmetricFabricPackage() {
			SymmetricPackageTest ("SymmetricFabricPackage", ObscurCore.Packaging.PayloadLayoutScheme.Fabric);
		}
		#endif

		private void SymmetricPackageTest(string testName, ObscurCore.Packaging.PayloadLayoutScheme scheme) {
			// Process of writing destroys preKey variable passed in for security
			// We must copy it to a local variable before reading the package back
			var preKeyEnumerated = KeyProviders.Alice.SymmetricKeys.First();
			var preKey = new byte[preKeyEnumerated.Length];
			Array.Copy(preKeyEnumerated, preKey, preKey.Length);

			TimeSpan enc, dec;
			using (var ms = new MemoryStream ()) {
				var sw = Stopwatch.StartNew ();
				var package = new Package (preKey, scheme);
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
				var readingPackage = Package.FromStream (ms, KeyProviders.Alice);
				readingPackage.ReadToDirectory (IOTestBase.PackageDestinationDirectory.FullName);
				sw.Stop ();
				dec = sw.Elapsed;
			}

			Assert.Pass ("Packaging: {0} ms.\nDepackaging: {1} ms.", enc.Milliseconds, dec.Milliseconds);
		}

		// EC-UM1



		// Curve25519-UM1

		[Test]
		public void Curve25519UM1SimplePackage() {
			Curve25519UM1PackageTest ("Curve25519UM1SimplePackage", ObscurCore.Packaging.PayloadLayoutScheme.Simple);
		}

		[Test]
		public void Curve25519UM1FrameshiftPackage() {
			Curve25519UM1PackageTest ("Curve25519UM1FrameshiftPackage", ObscurCore.Packaging.PayloadLayoutScheme.Frameshift);
		}

		#if INCLUDE_FABRIC
		[Test]
		public void Curve25519UM1FabricPackage() {
			Curve25519UM1PackageTest ("Curve25519UM1FabricPackage", ObscurCore.Packaging.PayloadLayoutScheme.Fabric);
		}
		#endif

		private void Curve25519UM1PackageTest(string testName, ObscurCore.Packaging.PayloadLayoutScheme scheme) {
			// Process of writing destroys sender and receiver key variables passed in for security
			// We must copy it to a local variable before reading the package back
			var senderKeyEnumerated = KeyProviders.Alice.Curve25519Keypairs.First().Private;
			var senderKey = new byte[senderKeyEnumerated.Length];
			Array.Copy(senderKeyEnumerated, senderKey, senderKey.Length);
			var receiverKeyEnumerated = KeyProviders.Bob.Curve25519Keypairs.Last().Public;
			var receiverKey = new byte[receiverKeyEnumerated.Length];
			Array.Copy(receiverKeyEnumerated, receiverKey, receiverKey.Length);

			TimeSpan enc, dec;
			using (var ms = new MemoryStream ()) {
				var sw = Stopwatch.StartNew ();
				var package = new Package (senderKey, receiverKey, scheme);
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
				var readingPackage = Package.FromStream (ms, KeyProviders.Bob);
				readingPackage.ReadToDirectory (IOTestBase.PackageDestinationDirectory.FullName);
				sw.Stop ();
				dec = sw.Elapsed;
			}

			Assert.Pass ("Packaging: {0} ms.\nDepackaging: {1} ms.", enc.Milliseconds, dec.Milliseconds);
		}

    }
}
