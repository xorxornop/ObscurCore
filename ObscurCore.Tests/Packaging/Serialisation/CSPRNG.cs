using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging.Serialisation
{
    class CSPRNG : SerialisationTestBase
    {
        [Test]
        public void SOSEMANUK () {
            var inputObj = Source.CreateStreamCipherCSPRNGConfiguration(SymmetricStreamCiphers.SOSEMANUK);

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<StreamCipherCSPRNGConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

    }
}
