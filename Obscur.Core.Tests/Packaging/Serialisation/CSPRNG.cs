using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using Obscur.Core.Cryptography.Entropy;
using Obscur.Core.DTO;

namespace ObscurCore.Tests.Packaging.Serialisation
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
