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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.DTO;

namespace Obscur.Core.Packaging.Multiplexing.Primitives
{
    /// <summary>
    ///     Derived payload multiplexer implementing random-data item headers and trailers
    ///     of either fixed or PRNG-varied length.
    /// </summary>
    public sealed class FrameshiftPayloadMux : SimplePayloadMux
    {
        /// <summary>
        ///     Minimum permissible padding length.
        /// </summary>
        /// <remarks>
        ///     Must be constant within a given DTO version lifetime (<see cref="Athena.Packaging.PackageFormatVersion"/>).
        /// </remarks>
        public const int MinimumPaddingLength = 8;

        /// <summary>
        ///     Maximum permissible padding length.
        /// </summary>
        /// <remarks>
        ///     Must be constant within a given DTO version lifetime (<see cref="Athena.Packaging.PackageFormatVersion"/>).
        /// </remarks>
        public const int MaximumPaddingLength = 512;

        /// <summary>
        ///     Default length for fixed-length padding to use in configurations.
        /// </summary>
        public const int DefaultFixedPaddingLength = 64;

        /// <summary>
        ///     Used for <see cref="PayloadMuxEntropyScheme.Preallocation" /> scheme. Size in bytes.
        /// </summary>
        /// <remarks>
        ///     Must be constant within a given DTO version lifetime (<see cref="Athena.Packaging.PackageFormatVersion"/>).
        /// </remarks>
        internal const int PaddingFieldMaximumSize = sizeof(UInt16);

        private readonly int _maxPadding;
        private readonly int _minPadding;
        private readonly FrameshiftPaddingMode _paddingMode;
        private readonly byte[] _paddingBuffer;

        /// <summary>
        ///     Initializes a new instance of a stream multiplexer.
        /// </summary>
        /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
        /// <param name="multiplexedStream">
        ///     Stream being written to (destination; multiplexing) or read from (source;
        ///     demultiplexing).
        /// </param>
        /// <param name="payloadItems">Payload items to write.</param>
        /// <param name="itemPreKeys">Pre-keys for items (indexed by item identifiers).</param>
        /// <param name="config">Configuration of stream selection and padding scheme.</param>
        public FrameshiftPayloadMux(bool writing, Stream multiplexedStream, IReadOnlyList<PayloadItem> payloadItems,
                                    IReadOnlyDictionary<Guid, byte[]> itemPreKeys, PayloadConfiguration config)
            : base(writing, multiplexedStream, payloadItems, itemPreKeys, config)
        {
            var frameshiftConfig =
                config.SchemeConfiguration.DeserialiseDto<RangeConfiguration>();
            if (frameshiftConfig.Minimum < MinimumPaddingLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Minimum padding length is below specification minimum.");
            }
            if (frameshiftConfig.Maximum < MaximumPaddingLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Maximum padding length is above specification maximum.");
            }

            _minPadding = frameshiftConfig.Minimum;
            _maxPadding = frameshiftConfig.Maximum;
            _paddingMode = _minPadding == _maxPadding
                ? FrameshiftPaddingMode.FixedLength
                : FrameshiftPaddingMode.VariableLength;
            _paddingBuffer = new byte[_maxPadding];
        }

        private int NextPaddingLength()
        {
            int paddingLength = (_paddingMode == FrameshiftPaddingMode.VariableLength)
                ? EntropySource.NextPositive(_minPadding, _maxPadding)
                : _maxPadding;
            Debug.Print(DebugUtility.CreateReportString("FrameshiftPayloadMux", "NextPaddingLength", "Generated length value",
                paddingLength));

            return paddingLength;
        }

        /// <inheritdoc />
        protected override int GetHeaderLength()
        {
            return NextPaddingLength();
        }

        /// <inheritdoc />
        protected override void EmitHeader(MacStream authenticator)
        {
            int paddingLength = GetHeaderLength();
            StratCom.EntropySupplier.NextBytes(_paddingBuffer, 0, paddingLength);
            authenticator.Write(_paddingBuffer, 0, paddingLength);
            Overhead += paddingLength;
        }

        /// <inheritdoc />
        protected override void ConsumeHeader(MacStream authenticator)
        {
            int paddingLength = GetHeaderLength();
            int bytesRead = authenticator.Read(_paddingBuffer, 0, paddingLength);
            if (bytesRead < paddingLength) {
#if DEBUG
                string exStr = String.Format("Unable to read frameshift padding bytes ({0} bytes returned of a requested {1}).",
                    bytesRead, paddingLength);
#else
                string exStr = "Unable to read frameshift padding bytes.";
#endif
                throw new IOException(exStr);
            }
            Overhead += paddingLength;
        }

        /// <inheritdoc />
        protected override int GetTrailerLength()
        {
            return NextPaddingLength();
        }

        /// <inheritdoc />
        protected override void EmitTrailer(MacStream authenticator)
        {
            EmitHeader(authenticator);
        }

        /// <inheritdoc />
        protected override void ConsumeTrailer(MacStream authenticator)
        {
            ConsumeHeader(authenticator);
        }
    }
}
