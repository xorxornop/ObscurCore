//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{	
	public static class PayloadLayoutConfigurationFactory
	{
		/// <summary>
		/// Initialises the configuration for the specified module type with default settings. 
		/// If fine-tuning is desired, use the specialised constructors.
		/// </summary>
		/// <param name="schemeEnum">Desired payload layout scheme.</param>
		public static PayloadConfiguration CreateDefault(PayloadLayoutSchemes schemeEnum) {
			var config = new PayloadConfiguration {
                SchemeName = schemeEnum.ToString(),
				PrimaryPRNGName = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
				PrimaryPRNGConfiguration = Source.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
			};
			
			switch (schemeEnum) {
			case PayloadLayoutSchemes.Simple:
				break;
			case PayloadLayoutSchemes.Frameshift:
				// Padding length is variable by default.
			    var frameshiftConfig = new PayloadSchemeConfiguration() {
			            Minimum = FrameshiftMux.MinimumPaddingLength,
			            Maximum = FrameshiftMux.MaximumPaddingLength
			        };
			    config.SchemeConfiguration = frameshiftConfig.SerialiseDTO();
				break;
#if(INCLUDE_FABRIC)
            case PayloadLayoutSchemes.Fabric:
				// Stripe length is variable by default.
				var fabricConfig = new PayloadSchemeConfiguration() {
			            Minimum = FabricMux.MinimumStripeLength,
			            Maximum = FabricMux.MaximumStripeLength
			        };
			    config.SchemeConfiguration = fabricConfig.SerialiseDTO();
				break;
#endif
			}
			
			return config;
		}

        public static PayloadConfiguration CreateFrameshiftFixed(CsPseudorandomNumberGenerator csprngEnum) {
            return CreateFrameshiftFixed(csprngEnum, null);
        }
		
		public static PayloadConfiguration CreateFrameshiftFixed(CsPseudorandomNumberGenerator csprngEnum, int? stripeSize) {
            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutSchemes.Frameshift.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = (stripeSize == null ? FrameshiftMux.DefaultFixedPaddingLength : stripeSize.Value),
			            Maximum = (stripeSize == null ? FrameshiftMux.DefaultFixedPaddingLength : stripeSize.Value),
			        }.SerialiseDTO(),
				PrimaryPRNGName = csprngEnum.ToString(),
				PrimaryPRNGConfiguration = Source.CreateStreamCipherCsprngConfiguration(
                    csprngEnum).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
			};
		    return config;
		}

        public static PayloadConfiguration CreateFrameshiftVariable(CsPseudorandomNumberGenerator csprngEnum) {
            return CreateFrameshiftVariable(csprngEnum, null, null);
        }

	    public static PayloadConfiguration CreateFrameshiftVariable(CsPseudorandomNumberGenerator csprngEnum, int? minStripe, int? maxStripe) {
            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutSchemes.Frameshift.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = (minStripe == null ? FrameshiftMux.MinimumPaddingLength : minStripe.Value),
			            Maximum = (maxStripe == null ? FrameshiftMux.MaximumPaddingLength : maxStripe.Value)
			        }.SerialiseDTO(),
				PrimaryPRNGName = csprngEnum.ToString(),
				PrimaryPRNGConfiguration = Source.CreateStreamCipherCsprngConfiguration(
                    csprngEnum).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
			};
            return config;
	    }
#if INCLUDE_FABRIC
	    public static PayloadConfiguration CreateFabricFixed(CSPRNumberGenerators generator, int? stripeSize = null) {
            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutSchemes.Frameshift.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = (stripeSize == null ? FrameshiftMux.DefaultFixedPaddingLength : stripeSize.Value),
			            Maximum = (stripeSize == null ? FrameshiftMux.DefaultFixedPaddingLength : stripeSize.Value),
			        }.SerialiseDTO(),
				PrimaryPRNGName = generator.ToString(),
				PrimaryPRNGConfiguration = Source.CreateStreamCipherCSPRNGConfiguration(
                    generator).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
			};
		    return config;
		}

	    public static PayloadConfiguration CreateFabricVariable(CSPRNumberGenerators generator, int? minStripe = null, int? maxStripe = null) {
            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutSchemes.Fabric.ToString(),
                SchemeConfiguration = new PayloadSchemeConfiguration() {
			            Minimum = (minStripe == null ? FabricMux.MinimumStripeLength : minStripe.Value),
			            Maximum = (maxStripe == null ? FrameshiftMux.MaximumStripeLength : maxStripe.Value)
			        }.SerialiseDTO(),
				PrimaryPRNGName = generator.ToString(),
				PrimaryPRNGConfiguration = Source.CreateStreamCipherCSPRNGConfiguration(
                    generator).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
			};
            return config;
	    }
#endif
	}

}
