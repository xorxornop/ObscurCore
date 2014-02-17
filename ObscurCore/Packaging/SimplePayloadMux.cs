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
using System.Diagnostics;
using System.IO;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.DTO;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Packaging
{
	/// <summary>
	/// Payload multiplexer implementing stream selection order by CSPRNG.
	/// </summary>
	public class SimplePayloadMux : PayloadMux
	{
		protected const int BufferSize = 4096;
		protected readonly byte[] Buffer = new byte[BufferSize];
		protected readonly Csprng SelectionSource;

        /// <summary>
		/// Initializes a new instance of a payload multiplexer.
	    /// </summary>
		/// <param name="writing">If set to <c>true</c>, writing a multiplexed stream (payload); otherwise, reading.</param>
	    /// <param name="multiplexedStream">Stream being written to (destination; multiplexing) or read from (source; demultiplexing).</param>
		/// <param name="payloadItems">Payload items to write.</param>
		/// <param name="itemPreKeys">Pre-keys for items (indexed by item identifiers).</param>
	    /// <param name="config">Configuration of stream selection.</param>
		public SimplePayloadMux (bool writing, Stream multiplexedStream, IReadOnlyList<PayloadItem> payloadItems, 
			IReadOnlyDictionary<Guid, byte[]> itemPreKeys, IPayloadConfiguration config) 
			: base(writing, multiplexedStream, payloadItems, itemPreKeys)
		{
			if (config == null)
				throw new ArgumentNullException ("config");

			SelectionSource = Source.CreateCsprng(config.PrngName.ToEnum<CsPseudorandomNumberGenerator>(),
		        config.PrngConfiguration);
		    NextSource();
		}

		public int Overhead { get; protected set; }

		protected override void ExecuteOperation () {
			var item = PayloadItems[Index];
			var itemIdentifier = item.Identifier;
			DecoratingStream itemDecorator;
			MacStream itemAuthenticator;

			CreateEtMSchemeStreams (item, out itemDecorator, out itemAuthenticator);

			Overhead += Writing ? EmitHeader(itemAuthenticator) : ConsumeHeader(itemAuthenticator);

			if(Writing) {
				int iterIn = 0;
				do {
					iterIn = item.StreamBinding.Read(Buffer, 0, BufferSize);
					itemDecorator.Write(Buffer, 0, iterIn);
				} while (iterIn > 0);
			} else {
				itemDecorator.ReadExactlyTo (item.StreamBinding, item.InternalLength, true);
			}

			// Item is finished, we need to do some things.
			itemDecorator.Close ();
			Overhead += Writing ? EmitTrailer(itemAuthenticator) : ConsumeTrailer(itemAuthenticator);

			// Length checks & commits
			if(Writing) {
				// Check if pre-stated length matches what was actually written
				if(item.ExternalLength > 0 && itemDecorator.BytesIn != item.ExternalLength) {
					throw new InvalidDataException ("Mismatch between stated item external length and actual input length.");
				}
				// Commit the determined internal length to item in payload manifest
				item.InternalLength = itemDecorator.BytesOut;
			} else {
				if(itemDecorator.BytesIn != item.InternalLength) {
					throw new InvalidOperationException ("Probable decorator stack malfunction.");
				}
				if(itemDecorator.BytesOut != item.ExternalLength) {
					throw new InvalidDataException ("Mismatch between stated item external length and actual output length.");
				}
			}

			// Final stages of Encrypt-then-MAC authentication scheme
			byte[] itemDtoAuthBytes = item.CreateAuthenticatibleClone().SerialiseDto ();
			itemAuthenticator.Update (itemDtoAuthBytes, 0, itemDtoAuthBytes.Length);
			itemAuthenticator.Close ();

			// Authentication
			if(Writing) {
				// Commit the MAC to item in payload manifest
				item.AuthenticationVerifiedOutput = itemAuthenticator.Mac.DeepCopy();
			} else {
				// Verify the authenticity of the item ciphertext and configuration
				if (itemAuthenticator.Mac.SequenceEqualConstantTime(item.AuthenticationVerifiedOutput) == false) {
					// Verification failed!
					throw new CiphertextAuthenticationException ("Payload item not authenticated.");
				}
			}

			// Mark the item as completed in the register
			ItemCompletionRegister[Index] = true;
			ItemsCompleted++;
			// Close the source/destination
			item.StreamBinding.Close();
			Debug.Print(DebugUtility.CreateReportString("SimplePayloadMux", "ExecuteOperation", "[*** END OF ITEM",
				Index + " ***]"));
		}

	    /// <summary>
		/// Advances and returns the index of the next stream to use in an I/O operation (whether to completion or just a buffer-full).
		/// </summary>
		/// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
		/// <returns>The next stream index.</returns>
		protected override sealed void NextSource() {
			Index = SelectionSource.Next(0, PayloadItems.Count);
			Debug.Print(DebugUtility.CreateReportString("SimplePayloadMux", "NextSource", "Generated index",
                    Index));
		}

		protected virtual int EmitHeader(MacStream authenticator) {
			// Unused in this version
			return 0;
		}

		protected virtual int EmitTrailer(MacStream authenticator) {
			// Unused in this version
			return 0;
		}

		protected virtual int ConsumeHeader(MacStream authenticator) {
			// Unused in this version
			// Could throw an exception in an implementation where a header must be present
			return 0;
		}

		protected virtual int ConsumeTrailer(MacStream authenticator) {
			// Unused in this version
			// Could throw an exception in an implementation where a trailer must be present
			return 0;
		}

	}
}
