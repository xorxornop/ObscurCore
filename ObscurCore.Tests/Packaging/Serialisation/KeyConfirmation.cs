using System.IO;
using NUnit.Framework;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging.Serialisation
{
    class KeyConfirmation : SerialisationTestBase
    {
        [Test]
        public void KeyConfirmationTest () {
            var inputObj = new KeyConfirmationConfiguration() {
                SchemeName = "TestForNow",
                SchemeConfiguration = new byte[] { 0x01, 0x02, 0x03 },
                Salt = new byte[] { 0x03, 0x01, 0x04 },
                Hash = new byte[] { 0x03, 0x02, 0x01 }
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<KeyConfirmationConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }
    }
}
