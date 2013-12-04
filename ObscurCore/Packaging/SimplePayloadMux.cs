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
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
	/// <summary>
	/// Derived stream mux implementing stream selection with PRNG initialised with seed parameters.
	/// </summary>
	public class SimplePayloadMux : PayloadMux
	{
	    private readonly Csprng _selectionSource;

        /// <summary>
	    /// Initializes a new instance of a stream multiplexer.
	    /// </summary>
	    /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
	    /// <param name="multiplexedStream">Stream being written to (destination; multiplexing) or read from (source; demultiplexing).</param>
	    /// <param name="streams">Streams being read from (sources; multiplexing), or written to (destinations; demultiplexing).</param>
	    /// <param name="transforms">Transform funcs.</param>
	    /// <param name="config">Configuration of stream selection.</param>
		public SimplePayloadMux (bool writing, Stream multiplexedStream, IList<IStreamBinding> streams, IList<Func<Stream, DecoratingStream>> transforms, 
		                  IPayloadConfiguration config) : base(writing, multiplexedStream, streams, transforms)
		{
			_selectionSource = Source.CreateCsprng(config.PrimaryPrngName.ToEnum<CsPseudorandomNumberGenerator>(),
		        config.PrimaryPrngConfiguration);

		    NextSource();
		}

	    protected internal Csprng SelectionSource {
	        get { return _selectionSource; }
	    }

	    /// <summary>
		/// Advances and returns the index of the next stream to use in an I/O operation (whether to completion or just a buffer-full).
		/// </summary>
		/// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
		/// <returns>The next stream index.</returns>
		protected override sealed int NextSource() {
		    CurrentIndex = _selectionSource.Next(0, ItemCount - 1);

            Debug.Print(DebugUtility.CreateReportString("SimplePayloadMultiplexer", "NextSource", "Generated index",
                    CurrentIndex));

			return CurrentIndex;
		}
	}
}

