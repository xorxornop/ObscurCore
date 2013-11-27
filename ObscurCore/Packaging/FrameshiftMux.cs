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
	/// <summary>
	/// Derived stream mux implementing stream selection with PRNG, 
	/// and random-data item headers & trailers of constant or PRNG-varied length.
	/// </summary>
	public sealed class FrameshiftMux : SimpleMux
	{
		public const int	MinimumPaddingLength 		= 8,
							MaximumPaddingLength 		= 256,
							DefaultFixedPaddingLength 	= 32;

		//protected readonly Random prngPadding;
	    private readonly FrameshiftPaddingModes _mode;
	    private readonly int _minPadding, _maxPadding;
	    private readonly Random _paddingSrc = StratCom.EntropySource;
		
		public FrameshiftMux (bool writing, Stream multiplexedStream, IList<IStreamBinding> streams, IList<Func<Stream, DecoratingStream>> transforms, 
		                      IPayloadConfiguration config) : base(writing, multiplexedStream, streams, transforms, config)
		{
			var frameshiftConfig = StratCom.DeserialiseDTO<PayloadSchemeConfiguration>(config.SchemeConfiguration);
		    _minPadding = frameshiftConfig.Minimum;
		    _maxPadding = frameshiftConfig.Maximum;
			
			if (_minPadding < MinimumPaddingLength)
				throw new ArgumentOutOfRangeException("config", "Minimum padding length is set below specification minimum.");
			if (_maxPadding < MaximumPaddingLength)
				throw new ArgumentOutOfRangeException("config", "Maximum padding length is set above specification maximum.");

            _mode = _minPadding == _maxPadding ? FrameshiftPaddingModes.FixedLength : FrameshiftPaddingModes.VariableLength;

            /*if (mode == FrameshiftPaddingModes.VariableLength) {
                prngPadding = Source.CreateCSPRNG(config.SecondaryPRNGName.ToEnum<CSPRNumberGenerators>(),
		        config.SecondaryPRNGConfiguration);
            }*/
		}

		protected override int EmitHeader () { return EmitPadding(); }
		
		protected override int EmitTrailer () { return EmitHeader(); }

        private int EmitPadding () {
            var paddingLength = (_mode == FrameshiftPaddingModes.VariableLength) ? SelectionSource.Next(_minPadding, _maxPadding) : _maxPadding;

            Debug.Print(DebugUtility.CreateReportString("FrameshiftMux", "EmitPadding", "Padding length",
                    paddingLength.ToString()));

            var paddingBuffer = new byte[paddingLength];
            _paddingSrc.NextBytes(paddingBuffer);
            CurrentDestination.Write(paddingBuffer, 0, paddingLength);
            return paddingLength;
        }
		
		protected override int ConsumeHeader () { return ConsumePadding(); }
		
		protected override int ConsumeTrailer () { return ConsumePadding(); }
		
		private int ConsumePadding() {
            var paddingLength = (_mode == FrameshiftPaddingModes.VariableLength) ? SelectionSource.Next(_minPadding, _maxPadding) : _maxPadding;

            Debug.Print(DebugUtility.CreateReportString("FrameshiftMux", "ConsumePadding", "Padding length",
                    paddingLength.ToString()));

			if (CurrentSource.CanSeek) CurrentSource.Seek(paddingLength, SeekOrigin.Current);
			else CurrentSource.Read(new byte[paddingLength], 0, paddingLength);
			return paddingLength;
		}
	}
	
}

