#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using System.IO;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.DTO;
using ObscurCore.Packaging.Multiplexing.Primitives;

namespace ObscurCore.Packaging.Multiplexing
{
    public static class PayloadLayoutConfigurationFactory
    {
        /// <summary>
        ///     Initialises the configuration for the specified module type with default settings.
        ///     If fine-tuning is desired, use the specialised constructors.
        /// </summary>
        /// <param name="schemeEnum">Desired payload layout scheme.</param>
        public static PayloadConfiguration CreateDefault(PayloadLayoutScheme schemeEnum)
        {
            const CsPseudorandomNumberGenerator defaultCsprng = CsPseudorandomNumberGenerator.Rabbit; // Fast initialisation!

            var config = new PayloadConfiguration {
                SchemeName = schemeEnum.ToString(),
                EntropyScheme = PayloadMuxEntropyScheme.StreamCipherCsprng,
                EntropySchemeData = CsPrngFactory.CreateStreamCipherCsprngConfiguration(defaultCsprng).SerialiseDto()
            };

            switch (schemeEnum) {
                case PayloadLayoutScheme.Simple:
                    break;
                case PayloadLayoutScheme.Frameshift:
                    // Padding length is variable by default.
                    var frameshiftConfig = new RangeConfiguration {
                        Minimum = FrameshiftPayloadMux.MinimumPaddingLength,
                        Maximum = FrameshiftPayloadMux.MaximumPaddingLength
                    };
                    config.SchemeConfiguration = frameshiftConfig.SerialiseDto();
                    break;
#if INCLUDE_FABRIC
                case PayloadLayoutScheme.Fabric:
                    // Stripe length is variable by default.
                    var fabricConfig = new RangeConfiguration {
                        Minimum = FabricPayloadMux.MinimumStripeLength,
                        Maximum = FabricPayloadMux.MaximumStripeLength
                    };
                    config.SchemeConfiguration = fabricConfig.SerialiseDto();
                    break;
#endif
            }

            return config;
        }

        public static PayloadConfiguration CreateFrameshiftFixed(CsPseudorandomNumberGenerator csprngEnum, int? paddingSize = null)
        {
            int fixedSize = paddingSize == null ? FrameshiftPayloadMux.DefaultFixedPaddingLength : paddingSize.Value;
            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutScheme.Frameshift.ToString(),
                SchemeConfiguration = new RangeConfiguration {
                    Minimum = fixedSize,
                    Maximum = fixedSize,
                }.SerialiseDto(),
                EntropyScheme = PayloadMuxEntropyScheme.StreamCipherCsprng,
                EntropySchemeData = CsPrngFactory.CreateStreamCipherCsprngConfiguration(csprngEnum).SerialiseDto()
            };
            return config;
        }

        public static PayloadConfiguration CreateFrameshiftVariable(CsPseudorandomNumberGenerator csprngEnum, int? minPadding = null,
                                                                    int? maxPadding = null)
        {
            CheckFrameshiftArgumentsValid(minPadding, maxPadding);

            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutScheme.Frameshift.ToString(),
                SchemeConfiguration = new RangeConfiguration {
                    Minimum = (minPadding == null ? FrameshiftPayloadMux.MinimumPaddingLength : minPadding.Value),
                    Maximum = (maxPadding == null ? FrameshiftPayloadMux.MaximumPaddingLength : maxPadding.Value)
                }.SerialiseDto(),
                EntropyScheme = PayloadMuxEntropyScheme.StreamCipherCsprng,
                EntropySchemeData = CsPrngFactory.CreateStreamCipherCsprngConfiguration(csprngEnum).SerialiseDto()
            };
            return config;
        }

        public static PayloadConfiguration CreateFrameshiftPrecomputedVariable(int items, int? minPadding = null,
                                                                               int? maxPadding = null)
        {
            if (items < 1) {
                throw new ArgumentOutOfRangeException("items");
            }

            CheckFrameshiftArgumentsValid(minPadding, maxPadding);

            int min = minPadding ?? FrameshiftPayloadMux.MinimumPaddingLength;
            int max = maxPadding ?? FrameshiftPayloadMux.MaximumPaddingLength;

            var entropyStream = new MemoryStream();
            bool[] itemCompletionRegister = new bool[items];
            int completedItems = 0;
            while (completedItems < items) {
                // Stream selection
                int stream;
                do {
                    stream = StratCom.EntropySupplier.Next(0, items);
                } while (itemCompletionRegister[stream]);

                entropyStream.WriteUInt32((uint) stream);
                int headerPaddingLength = StratCom.EntropySupplier.Next(min, max + 1);
                entropyStream.WriteUInt32((uint) headerPaddingLength);
                int trailerPaddingLength = StratCom.EntropySupplier.Next(min, max + 1);
                entropyStream.WriteUInt32((uint) trailerPaddingLength);

                itemCompletionRegister[stream] = true;
                completedItems++;
            }

            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutScheme.Frameshift.ToString(),
                SchemeConfiguration = new RangeConfiguration {
                    Minimum = min,
                    Maximum = max
                }.SerialiseDto(),
                EntropyScheme = PayloadMuxEntropyScheme.Preallocation,
                EntropySchemeData = entropyStream.ToArray()
            };
            return config;
        }

        private static void CheckFrameshiftArgumentsValid(int? minPadding = null, int? maxPadding = null)
        {
            if (minPadding != null) {
                if (minPadding.Value.IsBetween(
                    FrameshiftPayloadMux.MinimumPaddingLength, FrameshiftPayloadMux.MaximumPaddingLength) == false) {
                    throw new ArgumentOutOfRangeException("minPadding");
                }
            }
            if (maxPadding != null) {
                if (maxPadding.Value.IsBetween(
                    FrameshiftPayloadMux.MinimumPaddingLength, FrameshiftPayloadMux.MaximumPaddingLength) == false) {
                    throw new ArgumentOutOfRangeException("minPadding");
                }
            }
            if (minPadding != null && maxPadding != null) {
                if (maxPadding < minPadding) {
                    throw new ArgumentException("Maximum padding value is less than minimum.");
                }
            }
        }

#if INCLUDE_FABRIC
        public static PayloadConfiguration CreateFabricFixed(CsPseudorandomNumberGenerator csprngEnum, int? stripeSize = null)
        {
            int fixedSize = stripeSize == null ? FabricPayloadMux.DefaultFixedStripeLength : stripeSize.Value;
            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutScheme.Frameshift.ToString(),
                SchemeConfiguration = new RangeConfiguration {
                    Minimum = fixedSize,
                    Maximum = fixedSize,
                }.SerialiseDto(),
                EntropyScheme = PayloadMuxEntropyScheme.StreamCipherCsprng,
                EntropySchemeData = CsPrngFactory.CreateStreamCipherCsprngConfiguration(csprngEnum).SerialiseDto()
            };
            return config;
        }

        public static PayloadConfiguration CreateFabricVariable(CsPseudorandomNumberGenerator csprngEnum, int? minStripe = null,
                                                                int? maxStripe = null)
        {
            var config = new PayloadConfiguration {
                SchemeName = PayloadLayoutScheme.Fabric.ToString(),
                SchemeConfiguration = new RangeConfiguration {
                    Minimum = (minStripe == null ? FabricPayloadMux.MinimumStripeLength : minStripe.Value),
                    Maximum = (maxStripe == null ? FabricPayloadMux.MaximumStripeLength : maxStripe.Value)
                }.SerialiseDto(),
                EntropyScheme = PayloadMuxEntropyScheme.StreamCipherCsprng,
                EntropySchemeData = CsPrngFactory.CreateStreamCipherCsprngConfiguration(csprngEnum).SerialiseDto()
            };
            return config;
        }
#endif
    }
}
