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
using ObscurCore.Extensions.Generic;

namespace ObscurCore.Packaging
{	
	public class PayloadLayoutConfigurationFactory
	{
		/// <summary>
		/// Initialises the configuration for the specified module type with default settings. 
		/// If fine-tuning is desired, use the specialised constructors.
		/// </summary>
		/// <param name="scheme">Desired payload layout scheme.</param>
		public static PayloadLayoutConfiguration CreateDefault(PayloadLayoutSchemes scheme) {
			var config = new PayloadLayoutConfiguration {
                SchemeName = scheme.ToString(),
				PrimaryPRNGName = "SOSEMANUK",
				PrimaryPRNGConfiguration = Source.CreateStreamCipherCSPRNGConfiguration(
                    SymmetricStreamCiphers.SOSEMANUK).SerialiseDTO<StreamCipherCSPRNGConfiguration>()
			};
			
			switch (scheme) {
			case PayloadLayoutSchemes.Simple:
				break;
			case PayloadLayoutSchemes.Frameshift:
				// Padding length is variable by default.
				config.SchemeConfiguration =
					FrameshiftConfigurationUtility.WriteVariablePadding(
						FrameshiftMux.MinimumPaddingLength, FrameshiftMux.MaximumPaddingLength);
				break;
#if(INCLUDE_FABRIC)
            case PayloadLayoutSchemes.Fabric:
				// Stripe length is variable by default.
				config.SchemeConfiguration =
					FabricConfigurationUtility.WriteVariableStriping(FabricMux.MinimumStripeLength,
					                                                 FabricMux.MaximumStripeLength);
				break;
#endif
			}

			/*if(scheme != PayloadLayoutSchemes.Simple) {
				config.SecondaryPRNGName = "SOSEMANUK";
			    config.SecondaryPRNGConfiguration = Source.CreateStreamCipherCSPRNGConfiguration(
                    SymmetricStreamCiphers.SOSEMANUK).SerialiseDTO<StreamCipherCSPRNGConfiguration>();
			}*/
			
			return config;
		}
		
		/*public static PayloadLayoutConfiguration CreateFrameshift() {
            
        }*/
		
		/*public static PayloadLayoutConfiguration CreateFabric() {
            
        }*/
		
	}

}
