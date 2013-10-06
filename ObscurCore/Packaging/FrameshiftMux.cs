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
using System.IO;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Extensions.Enumerations;

namespace ObscurCore.Packaging
{
	/// <summary>
	/// Derived stream mux implementing stream selection with PRNG, 
	/// and random-data item headers & trailers of constant or PRNG-varied length.
	/// </summary>
	public class FrameshiftMux : SimpleMux
	{
		public const int	MinimumPaddingLength 		= 8,
							MaximumPaddingLength 		= 256,
							DefaultFixedPaddingLength 	= 32;

		//protected readonly Random prngPadding;
	    protected readonly FrameshiftPaddingModes mode;
		protected readonly int minPadding, maxPadding;
	    protected readonly Random paddingSrc = StratCom.EntropySource;
		
		public FrameshiftMux (bool writing, Stream multiplexedStream, IList<IStreamBinding> streams, IList<Func<Stream, DecoratingStream>> transforms, 
		                      IPayloadLayoutConfiguration config) : base(writing, multiplexedStream, streams, transforms, config)
		{
			FrameshiftConfigurationUtility.Read(config.SchemeConfiguration, out minPadding, out maxPadding);
			
			if (minPadding < MinimumPaddingLength)
				throw new ArgumentOutOfRangeException("config", "Minimum padding length is set below specification minimum.");
			if (maxPadding < MaximumPaddingLength)
				throw new ArgumentOutOfRangeException("config", "Maximum padding length is set above specification maximum.");

            mode = FrameshiftConfigurationUtility.CheckMode(minPadding, maxPadding);

            /*if (mode == FrameshiftPaddingModes.VariableLength) {
                prngPadding = Source.CreateCSPRNG(config.SecondaryPRNGName.ToEnum<CSPRNumberGenerators>(),
		        config.SecondaryPRNGConfiguration);
            }*/
		}

		protected override int EmitHeader () { return EmitPadding(); }
		
		protected override int EmitTrailer () { return EmitHeader(); }

        private int EmitPadding () {
            var paddingLength = (mode == FrameshiftPaddingModes.VariableLength) ? SelectionSource.Next(minPadding, maxPadding) : maxPadding;
            var paddingBuffer = new byte[paddingLength];
            paddingSrc.NextBytes(paddingBuffer);
            CurrentDestination.Write(paddingBuffer, 0, paddingLength);
            return paddingLength;
        }
		
		protected override int ConsumeHeader () { return ConsumePadding(); }
		
		protected override int ConsumeTrailer () { return ConsumePadding(); }
		
		private int ConsumePadding() {
            var paddingLength = (mode == FrameshiftPaddingModes.VariableLength) ? SelectionSource.Next(minPadding, maxPadding) : maxPadding;
			if (CurrentSource.CanSeek) CurrentSource.Seek(paddingLength, SeekOrigin.Current);
			else CurrentSource.Read(new byte[paddingLength], 0, paddingLength);
			return paddingLength;
		}
	}
	
}

