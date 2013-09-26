using System.IO;
using NUnit.Framework;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging.Serialisation
{
	class ManifestTests : SerialisationTestBase
	{
		[Test]
		public void Test() {
			var output = new MemoryStream ();

			var manifest = new Manifest ();

			serialiser.SerializeWithLengthPrefix (output, "", typeof(string), ProtoBuf.PrefixStyle.Base128, 0);

		}
	}
}

