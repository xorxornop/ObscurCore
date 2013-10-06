using System.IO;
using NUnit.Framework;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging.Serialisation
{
	class ManifestTests : SerialisationTestBase
	{
		[Test]
		public void Test() {

			var manifest = new Manifest ();

			var stream = SerialiseToMemory(manifest);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<KeyConfirmationConfiguration>(stream);

            bool equal = manifest.Equals(outputObj);

            Assert.IsTrue(equal);

		}
	}
}

