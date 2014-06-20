//
//  Copyright 2014  Matthew Ducker
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

// Controls whether items' padding is authenticated along with their actual content.
// Comment out to disable. Doing so will cause it to be out of ObscurCore specification.

#define AUTHENTICATE_FRAMESHIFT_PADDING

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
    /// <summary>
    /// Derived payload multiplexer implementing random-data item headers & trailers 
    /// of either constant or CSPRNG-varied length.
    /// </summary>
    public sealed class FrameshiftPayloadMux : SimplePayloadMux
    {
        public const int MinimumPaddingLength = 8,
            MaximumPaddingLength = 512,
            DefaultFixedPaddingLength = 64;

        private readonly FrameshiftPaddingMode _paddingMode;
        private readonly int _minPadding, _maxPadding;
        private readonly byte[] _paddingBuffer;

        /// <summary>
        /// Initializes a new instance of a stream multiplexer.
        /// </summary>
        /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
        /// <param name="multiplexedStream">Stream being written to (destination; multiplexing) or read from (source; demultiplexing).</param>
        /// <param name="payloadItems">Payload items to write.</param>
        /// <param name="itemPreKeys">Pre-keys for items (indexed by item identifiers).</param>
        /// <param name="config">Configuration of stream selection and padding scheme.</param>
        public FrameshiftPayloadMux(bool writing, Stream multiplexedStream, IReadOnlyList<PayloadItem> payloadItems,
            IReadOnlyDictionary<Guid, byte[]> itemPreKeys, IPayloadConfiguration config)
            : base(writing, multiplexedStream, payloadItems, itemPreKeys, config)
        {
            var frameshiftConfig =
                StratCom.DeserialiseDataTransferObject<PayloadSchemeConfiguration>(config.SchemeConfiguration);
            if (frameshiftConfig.Minimum < MinimumPaddingLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Minimum padding length is set below specification minimum.");
            }
            if (frameshiftConfig.Maximum < MaximumPaddingLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Maximum padding length is set above specification maximum.");
            }

            _minPadding = frameshiftConfig.Minimum;
            _maxPadding = frameshiftConfig.Maximum;
            _paddingMode = _minPadding == _maxPadding
                ? FrameshiftPaddingMode.FixedLength
                : FrameshiftPaddingMode.VariableLength;
            _paddingBuffer = new byte[_maxPadding];
        }

        protected override void EmitHeader(MacStream authenticator)
        {
            var paddingLength = (_paddingMode == FrameshiftPaddingMode.VariableLength)
                ? SelectionSource.Next(_minPadding, _maxPadding + 1)
                : _maxPadding;
            Debug.Print(DebugUtility.CreateReportString("FrameshiftPayloadMux", "EmitHeader/EmitTrailer",
                "Padding length",
                paddingLength));

            StratCom.EntropySupplier.NextBytes(_paddingBuffer, 0, paddingLength);

#if AUTHENTICATE_FRAMESHIFT_PADDING
            authenticator.Write(_paddingBuffer, 0, paddingLength);
#else
			authenticator.Binding.Write(_paddingBuffer, 0, paddingLength);
			#endif

            Overhead += paddingLength;
        }

        protected override void EmitTrailer(MacStream authenticator)
        {
            EmitHeader(authenticator);
        }

        protected override void ConsumeHeader(MacStream authenticator)
        {
            var paddingLength = (_paddingMode == FrameshiftPaddingMode.VariableLength)
                ? SelectionSource.Next(_minPadding, _maxPadding + 1)
                : _maxPadding;
            Debug.Print(DebugUtility.CreateReportString("FrameshiftPayloadMux", "ConsumeHeader/ConsumeTrailer",
                "Padding length",
                paddingLength));

            var bytesRead = 0;
#if AUTHENTICATE_FRAMESHIFT_PADDING
            bytesRead = authenticator.Read(_paddingBuffer, 0, paddingLength);
#else
			if (authenticator.Binding.CanSeek) {
				authenticator.Binding.Seek(paddingLength, SeekOrigin.Current);
				return paddingLength;
			}
			bytesRead = authenticator.Binding.Read(_paddingBuffer, 0, paddingLength);
			#endif
            if (bytesRead < paddingLength) {
                throw new IOException("Unable to read frameshift padding bytes.");
            }

            Overhead += paddingLength;
        }

        protected override void ConsumeTrailer(MacStream authenticator)
        {
            ConsumeHeader(authenticator);
        }
    }
}
