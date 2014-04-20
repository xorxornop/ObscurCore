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

using System;
using System.Collections.Generic;
using System.IO;

using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
	public static class PayloadMultiplexerFactory
	{
		/// <summary>
		/// Instantiates and returns a payload I/O module implementing the mode of operation that the
		/// instance this method was called from describes.
		/// </summary>
		/// <param name="schemeEnum">Payload layout scheme to choose the correspknding multiplexer.</param>
		/// <param name="writing">Whether the multiplexer will be multiplexing or demultiplexing.</param>
		/// <param name="multiplexedStream">Stream to multiplex/demultiplex to/from.</param>
		/// <param name="streams">Streams to multiplex/demultiplex to/from.</param>
		/// <param name="transforms">Transforms to apply to the payload items (e.g. encryption).</param>
		/// <param name="config">Configuration of the layout module/multiplexer.</param>
		/// <returns>
		/// An module object deriving from PayloadMultiplexer.
		/// </returns>
		public static PayloadMux CreatePayloadMultiplexer (PayloadLayoutScheme schemeEnum, bool writing, 
			Stream multiplexedStream, List<PayloadItem> payloadItems, IReadOnlyDictionary<Guid, byte[]> itemPreKeys, 
			IPayloadConfiguration config)
		{
			switch (schemeEnum) {
			case PayloadLayoutScheme.Simple:
				return new SimplePayloadMux (writing, multiplexedStream, payloadItems, itemPreKeys, config);
			case PayloadLayoutScheme.Frameshift:
				return new FrameshiftPayloadMux(writing, multiplexedStream, payloadItems, itemPreKeys, config);
#if INCLUDE_FABRIC
			case PayloadLayoutScheme.Fabric:
				return new FabricPayloadMux(writing, multiplexedStream, payloadItems, itemPreKeys, config);
#endif
			default:
				throw new ArgumentException ("Scheme unsupported.", "schemeEnum");
			}
		}
	}
}
