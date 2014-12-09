using System.IO;
using NUnit.Framework;
using Obscur.Core.Cryptography.Entropy;
using Obscur.Core.DTO;

namespace Obscur.Core.Tests.Packaging.Serialisation
{
    class CSPRNG : SerialisationTestBase
    {
        [Test]
        public void SOSEMANUK () {
			var inputObj = CsPrngFactory.CreateStreamCipherCsprngConfiguration(CsPseudorandomNumberGenerator.Sosemanuk);

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<StreamCipherCsprngConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

    }
}
