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
    /// Derived payload multiplexer implementing item layout in stripes of either 
	/// constant or PRNG-varied length.
	/// </summary>
	public sealed class FabricPayloadMux : SimplePayloadMux
	{
		public const int 	MinimumStripeLength         = 8,
							MaximumStripeLength         = 65536,
							DefaultFixedStripeLength    = 4096;

		//protected readonly Csprng PrngStripe;
        private readonly FabricStripeMode _mode;
        private readonly int _minStripe, _maxStripe;

        /// <summary>
	    /// Initializes a new instance of a stream multiplexer.
	    /// </summary>
	    /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
	    /// <param name="multiplexedStream">Stream being written to (destination; multiplexing) or read from (source; demultiplexing).</param>
	    /// <param name="streams">Streams being read from (sources; multiplexing), or written to (destinations; demultiplexing).</param>
	    /// <param name="transforms">Transform funcs.</param>
	    /// <param name="config">Configuration of stream selection and stripe scheme.</param>
		public FabricPayloadMux (bool writing, Stream multiplexedStream, Manifest payloadManifest, 
			IPayloadConfiguration config) : base(writing, multiplexedStream, payloadManifest, config)
        {
		    var fabricConfig = StratCom.DeserialiseDataTransferObject<PayloadSchemeConfiguration>(config.SchemeConfiguration);
		    _minStripe = fabricConfig.Minimum;
		    _maxStripe = fabricConfig.Maximum;

			if (_minStripe < MinimumStripeLength)
				throw new ArgumentOutOfRangeException("config", "Minimum stripe length is set below specification minimum.");
			if (_maxStripe > MaximumStripeLength)
				throw new ArgumentOutOfRangeException("config", "Maximum stripe length is set above specification minimum.");

		    _mode = _minStripe == _maxStripe ? FabricStripeMode.FixedLength : FabricStripeMode.VariableLength;

            //if(mode == FabricStripeMode.VariableLength) {
            //    PrngStripe = Source.CreateCsprng(config.SecondaryPRNGName.ToEnum<CsPseudorandomNumberGenerator>(),
            //        config.SecondaryPRNGConfiguration);
            //}
		}
		
		/// <summary>
		/// If variable striping mode is enabled, advances the state of the stripe length selection PRNG (StripePRNG), 
		/// and returns the length of the next I/O operation to take place.
		/// </summary>
		/// <returns>The operation length.</returns>
		protected override long NextOperationLength() {
		    var opLen = _mode == FabricStripeMode.VariableLength ? SelectionSource.Next(_minStripe, _maxStripe) : _maxStripe;

            Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "NextOperationLength", "Generated stripe length",
                    opLen));

		    return opLen;
		}
	}
#endif
}

