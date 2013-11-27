using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging.Serialisation
{
    class PayloadLayout : SerialisationTestBase
    {
        [Test]
        public void Simple () {

            var inputObj = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Simple);

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Frameshift_Fixed () {
            var inputObj = new PayloadConfiguration() {
                SchemeName = PayloadLayoutSchemes.Frameshift.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = FrameshiftMux.DefaultFixedPaddingLength,
			            Maximum = FrameshiftMux.DefaultFixedPaddingLength
			        }.SerialiseDTO(),
                PrimaryPRNGName = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
                PrimaryPRNGConfiguration = Source.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Frameshift_Variable () {
            var inputObj = new PayloadConfiguration() {
                SchemeName = PayloadLayoutSchemes.Frameshift.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = FrameshiftMux.MinimumPaddingLength,
			            Maximum = FrameshiftMux.MaximumPaddingLength
			        }.SerialiseDTO(),
                PrimaryPRNGName = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
                PrimaryPRNGConfiguration = Source.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

#if(INCLUDE_FABRIC)
        [Test]
        public void Fabric_Fixed () {

            var inputObj = new PayloadConfiguration() {
                SchemeName = PayloadLayoutSchemes.Fabric.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration {
			            Minimum = FabricMux.DefaultFixedStripeLength,
			            Maximum = FabricMux.DefaultFixedStripeLength
			        }.SerialiseDTO(),
                PrimaryPRNGName = CSPRNumberGenerators.SOSEMANUK.ToString(),
                PrimaryPRNGConfiguration = Source.CreateStreamCipherCSPRNGConfiguration(
                    SymmetricStreamCiphers.SOSEMANUK).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Fabric_Variable () {
            var inputObj = new PayloadConfiguration() {                                        
                SchemeName = PayloadLayoutSchemes.Fabric.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration {
			            Minimum = FabricMux.MinimumStripeLength,
			            Maximum = FabricMux.MaximumStripeLength
			        }.SerialiseDTO(),
                PrimaryPRNGName = CSPRNumberGenerators.Salsa20.ToString(),
                PrimaryPRNGConfiguration = Source.CreateStreamCipherCSPRNGConfiguration(
                    SymmetricStreamCiphers.SOSEMANUK).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }
#endif
    }
}
