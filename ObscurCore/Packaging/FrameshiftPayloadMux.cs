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
	/// Derived payload multiplexer implementing random-data item headers & trailers 
	/// of either constant or PRNG-varied length.
	/// </summary>
	public sealed class FrameshiftPayloadMux : SimplePayloadMux
	{
		public const int	MinimumPaddingLength 		= 8,
							MaximumPaddingLength 		= 256,
							DefaultFixedPaddingLength 	= 32;

		private const bool AuthenticatePadding = true;

		//protected readonly Random prngPadding;
	    private readonly FrameshiftPaddingMode _mode;
	    private readonly int _minPadding, _maxPadding;
	    private readonly byte[] _paddingBuffer;

	    /// <summary>
	    /// Initializes a new instance of a stream multiplexer.
	    /// </summary>
	    /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
	    /// <param name="multiplexedStream">Stream being written to (destination; multiplexing) or read from (source; demultiplexing).</param>
	    /// <param name="streams">Streams being read from (sources; multiplexing), or written to (destinations; demultiplexing).</param>
	    /// <param name="transforms">Transform funcs.</param>
	    /// <param name="config">Configuration of stream selection and padding scheme.</param>
		public FrameshiftPayloadMux (bool writing, Stream multiplexedStream, Manifest payloadManifest, IPayloadConfiguration config) 
			: base(writing, multiplexedStream, payloadManifest, config)
		{
			var frameshiftConfig = StratCom.DeserialiseDataTransferObject<PayloadSchemeConfiguration>(config.SchemeConfiguration);

            if (frameshiftConfig.Minimum < MinimumPaddingLength)
				throw new ArgumentOutOfRangeException("config", "Minimum padding length is set below specification minimum.");
			if (frameshiftConfig.Maximum < MaximumPaddingLength)
				throw new ArgumentOutOfRangeException("config", "Maximum padding length is set above specification maximum.");

		    _minPadding = frameshiftConfig.Minimum;
		    _maxPadding = frameshiftConfig.Maximum;
            _mode = _minPadding == _maxPadding ? FrameshiftPaddingMode.FixedLength : FrameshiftPaddingMode.VariableLength;
			_paddingBuffer = new byte[_maxPadding];

            /*if (mode == FrameshiftPaddingModes.VariableLength) {
                prngPadding = Source.CreateCsprng(config.SecondaryPRNGName.ToEnum<CsPseudorandomNumberGenerator>(),
		        config.SecondaryPRNGConfiguration);
            }*/
		}

		protected override int EmitHeader () {
			var paddingLength = (_mode == FrameshiftPaddingMode.VariableLength) ? SelectionSource.Next(_minPadding, _maxPadding) : _maxPadding;
			Debug.Print(DebugUtility.CreateReportString("FrameshiftPayloadMux", "EmitPadding", "Padding length",
				paddingLength));
			StratCom.EntropySource.NextBytes(_paddingBuffer, 0, paddingLength);

			if(AuthenticatePadding) {
				ItemStreamMacs[PayloadManifest.PayloadItems[Index].Identifier].Write(_paddingBuffer, 0, paddingLength);
			} else {
				ItemStreamMacs[PayloadManifest.PayloadItems[Index].Identifier].Binding.Write(_paddingBuffer, 0, paddingLength);
			}

			return paddingLength;
		}
		
		protected override int EmitTrailer () { return EmitHeader(); }

		protected override int ConsumeHeader () {
			var paddingLength = (_mode == FrameshiftPaddingMode.VariableLength) ? SelectionSource.Next(_minPadding, _maxPadding) : _maxPadding;
			Debug.Print(DebugUtility.CreateReportString("FrameshiftPayloadMux", "ConsumePadding", "Padding length",
				paddingLength));

			var itemIdentifier = PayloadManifest.PayloadItems[Index].Identifier;

			if(AuthenticatePadding) {
				int bytesRead = ItemStreamMacs[itemIdentifier].Binding.Read (_paddingBuffer, 0, paddingLength);
				if(bytesRead < paddingLength) {
					throw new IOException ("Unable to read frameshift padding bytes.");
				}
				ItemStreamMacs[itemIdentifier].Update (_paddingBuffer, 0, paddingLength);
			} else {
				if (ItemStreamMacs[itemIdentifier].Binding.CanSeek) ItemStreamMacs[itemIdentifier].Binding.Seek(paddingLength, SeekOrigin.Current);
				else ItemStreamMacs[itemIdentifier].Binding.Read(new byte[paddingLength], 0, paddingLength);
			}
			return paddingLength;
		}
		
		protected override int ConsumeTrailer () { return ConsumeHeader(); }
	}
	
}

