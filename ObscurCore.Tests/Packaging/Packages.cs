using System;
using System.IO;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Tests.Cryptography;

namespace ObscurCore.Tests.Packaging
{
    public class Packages
    {
        [Test]
        public void SymmetricPackage() {
            // Process of writing destroys preKey variable passed in for security
            // We must copy it to a local variable before reading the package back
            var preKey = new byte[KeyProviders.Alice.SymmetricKeys.First().Length];
            Array.Copy(KeyProviders.Alice.SymmetricKeys.First(), preKey, preKey.Length);

            using (var ms = new MemoryStream()) {
                var package = new Package(preKey);
                foreach (var file in IOTestBase.SmallTextFileList) {
                    package.AddFile(file.FullName);
                }
                package.Write(ms, false);
                ms.Seek(0, SeekOrigin.Begin);
                // Now read it back
                var readingPackage = Package.FromStream(ms, KeyProviders.Alice);
                readingPackage.ReadToDirectory(IOTestBase.SmallTextFilesDestinationDirectory.FullName);
            }
        }

        [Test]
        public void Curve25519UM1Package() {
            // Process of writing destroys sender and receiver key variables passed in for security
            // We must copy it to a local variable before reading the package back
            var senderKeyEnumerated = KeyProviders.Alice.Curve25519Keypairs.First().Private;
            var senderKey = new byte[senderKeyEnumerated.Length];
            Array.Copy(senderKeyEnumerated, senderKey, senderKey.Length);
            var receiverKeyEnumerated = KeyProviders.Bob.Curve25519Keypairs.First().Public;
            var receiverKey = new byte[receiverKeyEnumerated.Length];
            Array.Copy(receiverKeyEnumerated, receiverKey, receiverKey.Length);

            using (var ms = new MemoryStream()) {
                var package = new Package(senderKey, receiverKey);
                foreach (var file in IOTestBase.SmallTextFileList) {
                    package.AddFile(file.FullName);
                }
                package.Write(ms, false);
                ms.Seek(0, SeekOrigin.Begin);
                // Now read it back
                var readingPackage = Package.FromStream(ms, KeyProviders.Bob);
                readingPackage.ReadToDirectory(IOTestBase.SmallTextFilesDestinationDirectory.FullName);
            }
        }
    }
}
