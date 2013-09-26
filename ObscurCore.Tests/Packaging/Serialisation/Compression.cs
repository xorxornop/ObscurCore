using System.IO;
using NUnit.Framework;

namespace ObscurCore.Tests.Packaging.Serialisation
{
    class Compression : SerialisationTestBase
    {
        [Test]
        public void Bzip2 () {
            var inputObj = new CompressionConfiguration() {
                AlgorithmName = CompressionAlgorithms.Deflate.ToString(),
                AlgorithmConfiguration = Bzip2ConfigurationUtility.Write(9)
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<CompressionConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Deflate () {
            var inputObj = new CompressionConfiguration() {
                AlgorithmName = CompressionAlgorithms.Deflate.ToString(),
                AlgorithmConfiguration = DeflateConfigurationUtility.Write(CompressionLevel.Default)
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<CompressionConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void LZ4 () {
            var inputObj = new CompressionConfiguration() {
                AlgorithmName = CompressionAlgorithms.LZ4.ToString()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<CompressionConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }
    }
}
