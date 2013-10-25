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
	public class SimpleMux : StreamMux
	{
		protected CSPRNG SelectionSource;

		public SimpleMux (bool writing, Stream multiplexedStream, IList<IStreamBinding> streams, IList<Func<Stream, DecoratingStream>> transforms, 
		                  IPayloadLayoutConfiguration config, int maxOpSize = 16384) : base(writing, multiplexedStream, streams, transforms, maxOpSize)
		{
			SelectionSource = Source.CreateCSPRNG(config.PrimaryPRNGName.ToEnum<CSPRNumberGenerators>(),
		        config.PrimaryPRNGConfiguration);

		    NextSource();
		}

		/// <summary>
		/// Advances and returns the index of the next stream to use in an I/O operation (whether to completion or just a buffer-full).
		/// </summary>
		/// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
		/// <returns>The next stream index.</returns>
		protected override sealed int NextSource() {
		    CurrentIndex = SelectionSource.Next(0, ItemCount - 1);
            Debug.Print("NextSource() : " + CurrentIndex);
			return CurrentIndex;
		}
	}
}

