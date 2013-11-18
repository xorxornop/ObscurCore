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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
#if(INCLUDE_FABRIC)
    /// <summary>
	/// Fabric mux.
	/// </summary>
	public class FabricMux : SimpleMux
	{
		public const int 	MinimumStripeLength         = 8,
							MaximumStripeLength         = 65536,
							DefaultFixedStripeLength    = 4096;

		//protected readonly CSPRNG PrngStripe;
	    protected readonly FabricStripeModes mode;
		protected readonly int minStripe, maxStripe;

		public FabricMux (bool writing, Stream multiplexedStream, IList<IStreamBinding> streams, IList<Func<Stream, DecoratingStream>> transforms, 
			IPayloadConfiguration config) : base(writing, multiplexedStream, streams, transforms, config, MaximumStripeLength)
        {
		    var fabricConfig = StratCom.DeserialiseDTO<PayloadSchemeConfiguration>(config.SchemeConfiguration);
		    minStripe = fabricConfig.Minimum;
		    maxStripe = fabricConfig.Maximum;

			if (minStripe < MinimumStripeLength)
				throw new ArgumentOutOfRangeException("config", "Minimum stripe length is set below specification minimum.");
			if (maxStripe > MaximumStripeLength)
				throw new ArgumentOutOfRangeException("config", "Maximum stripe length is set above specification minimum.");

		    mode = minStripe == maxStripe ? FabricStripeModes.FixedLength : FabricStripeModes.VariableLength;

            //if(mode == FabricStripeModes.VariableLength) {
            //    PrngStripe = Source.CreateCSPRNG(config.SecondaryPRNGName.ToEnum<CSPRNumberGenerators>(),
            //        config.SecondaryPRNGConfiguration);
            //}
		}
		
		/// <summary>
		/// If variable striping mode is enabled, advances the state of the stripe length selection PRNG (StripePRNG), 
		/// and returns the length of the next I/O operation to take place.
		/// </summary>
		/// <returns>The operation length.</returns>
		protected override long NextOperationLength() {
		    var opLen = mode == FabricStripeModes.VariableLength ? SelectionSource.Next(minStripe, maxStripe) : maxStripe;

            Debug.Print(DebugUtility.CreateReportString("FrameshiftMux", "NextOperationLength", "Generated stripe length",
                    opLen.ToString()));

		    return opLen;
		}
	}
#endif
}

