using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging.Serialisation
{
    class PayloadLayout : SerialisationTestBase
    {
        [Test]
        public void Simple () {

            var inputObj = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutScheme.Simple);

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }

        [Test]
        public void Frameshift_Fixed () {
            var inputObj = new PayloadConfiguration() {
                SchemeName = PayloadLayoutScheme.Frameshift.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = FrameshiftPayloadMux.DefaultFixedPaddingLength,
			            Maximum = FrameshiftPayloadMux.DefaultFixedPaddingLength
			        }.SerialiseDto(),
                PrngName = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
				PrngConfiguration = CsPrngFactory.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk).SerialiseDto<StreamCipherCsprngConfiguration>()
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
                SchemeName = PayloadLayoutScheme.Frameshift.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = FrameshiftPayloadMux.MinimumPaddingLength,
			            Maximum = FrameshiftPayloadMux.MaximumPaddingLength
			        }.SerialiseDto(),
                PrngName = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
				PrngConfiguration = CsPrngFactory.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk).SerialiseDto<StreamCipherCsprngConfiguration>()
            };

            var stream = SerialiseToMemory(inputObj);
            stream.Seek(0, SeekOrigin.Begin);
            var outputObj = DeserialiseFromMemory<PayloadConfiguration>(stream);

            bool equal = inputObj.Equals(outputObj);

            Assert.IsTrue(equal);
        }
		
#if INCLUDE_FABRIC
        [Test]
        public void Fabric_Fixed () {

            var inputObj = new PayloadConfiguration() {
                SchemeName = PayloadLayoutScheme.Fabric.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration {
			            Minimum = FabricPayloadMux.DefaultFixedStripeLength,
			            Maximum = FabricPayloadMux.DefaultFixedStripeLength
			        }.SerialiseDto(),
                PrngName = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
				PrngConfiguration = CsprngFactory.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk).SerialiseDto()
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
                SchemeName = PayloadLayoutScheme.Fabric.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration {
			            Minimum = FabricPayloadMux.MinimumStripeLength,
			            Maximum = FabricPayloadMux.MaximumStripeLength
			        }.SerialiseDto(),
                PrngName = CsPseudorandomNumberGenerator.Salsa20.ToString(),
				PrngConfiguration = CsprngFactory.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk).SerialiseDto()
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
