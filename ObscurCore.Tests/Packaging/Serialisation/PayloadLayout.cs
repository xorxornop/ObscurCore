using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging.Serialisation
{
    class PayloadLayout : SerialisationTestBase
    {
        [Test]
        public void Simple () {
            var inputObj = new PayloadLayoutConfiguration() {
                SchemeName = PayloadLayoutSchemes.Simple.ToString(),
                StreamPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                StreamPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadLayoutConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Frameshift_Fixed () {
            var inputObj = new PayloadLayoutConfiguration() {
                SchemeName = PayloadLayoutSchemes.Frameshift.ToString(),
                SchemeConfiguration = FrameshiftConfigurationUtility.WriteFixedPadding(32),
                StreamPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                StreamPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom(),
                SecondaryPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                SecondaryPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadLayoutConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Frameshift_Variable () {
            var inputObj = new PayloadLayoutConfiguration() {
                SchemeName = PayloadLayoutSchemes.Frameshift.ToString(),
                SchemeConfiguration = FrameshiftConfigurationUtility.WriteVariablePadding(8, 128),
                StreamPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                StreamPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom(),
                SecondaryPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                SecondaryPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadLayoutConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

#if(INCLUDE_FABRIC)
        [Test]
        public void Fabric_Fixed () {
            var inputObj = new PayloadLayoutConfiguration() {
                SchemeName = PayloadLayoutSchemes.Fabric.ToString(),
                SchemeConfiguration = FabricConfigurationUtility.WriteFixedStriping(256),
                StreamPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                StreamPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom(),
                SecondaryPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                SecondaryPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadLayoutConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Fabric_Variable () {
            var inputObj = new PayloadLayoutConfiguration() {                                        
                SchemeName = PayloadLayoutSchemes.Fabric.ToString(),
                SchemeConfiguration = FabricConfigurationUtility.WriteVariableStriping(64, 2048),
                StreamPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                StreamPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom(),
                SecondaryPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                SecondaryPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadLayoutConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }
#endif
    }
}
