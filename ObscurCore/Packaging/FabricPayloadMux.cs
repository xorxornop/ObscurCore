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
using ObscurCore.DTO;
using RingByteBuffer;

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
							MaximumStripeLength         = 32768,
							DefaultFixedStripeLength    = 512;

		private readonly FabricStripeMode _stripeMode;
        private readonly int _minStripe, _maxStripe;

		private Dictionary<Guid, MuxItemResourceContainer> _activeItemResources = new Dictionary<Guid, MuxItemResourceContainer>();

		private class MuxItemResourceContainer
		{
			public MuxItemResourceContainer (DecoratingStream decorator, MacStream authenticator, int bufferCapacity)
			{
				this.Decorator = decorator;
				this.Authenticator = authenticator;
				this.Buffer = new Lazy<RingBufferStream> ( () => new RingBufferStream(bufferCapacity, false));
			}
			public DecoratingStream Decorator { get; private set; }
			public MacStream Authenticator { get; private set; }
			public Lazy<RingBufferStream> Buffer { get; private set; }
		}

        /// <summary>
		/// Initializes a new instance of a payload multiplexer.
	    /// </summary>
	    /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
	    /// <param name="multiplexedStream">Stream being written to (destination; multiplexing) or read from (source; demultiplexing).</param>
		/// <param name="payloadItems">Payload items to write.</param>
		/// <param name="itemPreKeys">Pre-keys for items (indexed by item identifiers).</param>
	    /// <param name="config">Configuration of stream selection and stripe scheme.</param>
		public FabricPayloadMux (bool writing, Stream multiplexedStream, List<PayloadItem> payloadItems, 
			IReadOnlyDictionary<Guid, byte[]> itemPreKeys, IPayloadConfiguration config) 
			: base(writing, multiplexedStream, payloadItems, itemPreKeys, config)
        {
		    var fabricConfig = StratCom.DeserialiseDataTransferObject<PayloadSchemeConfiguration>(config.SchemeConfiguration);
			if (fabricConfig.Minimum < MinimumStripeLength)
				throw new ArgumentOutOfRangeException("config", "Minimum stripe length is set below specification minimum.");
			if (fabricConfig.Maximum > MaximumStripeLength)
				throw new ArgumentOutOfRangeException("config", "Maximum stripe length is set above specification minimum.");

			_minStripe = fabricConfig.Minimum;
			_maxStripe = fabricConfig.Maximum;
			_stripeMode = _minStripe == _maxStripe ? FabricStripeMode.FixedLength : FabricStripeMode.VariableLength;
		}


		/// <summary>
		/// Create and bind Encrypt-then-MAC scheme components for an item. 
		/// Adds finished encrypter and MACer to mux item resource container.
		/// </summary>
		/// <param name="item">Item to prepare resources for.</param>
		private MuxItemResourceContainer CreateEtMSchemeResources(PayloadItem item) {
			DecoratingStream decorator;
			MacStream authenticator;
			CreateEtMSchemeStreams (item, out decorator, out authenticator);
			var container = new MuxItemResourceContainer (decorator, authenticator, _maxStripe);
			return container;
		}

		protected override void ExecuteOperation () {
			var item = PayloadItems[Index];
			var itemIdentifier = item.Identifier;
			MuxItemResourceContainer itemContainer;
			if(_activeItemResources.ContainsKey(itemIdentifier)) {
				itemContainer = _activeItemResources [itemIdentifier];
			} else {
				itemContainer = CreateEtMSchemeResources (item);
				_activeItemResources.Add (itemIdentifier, itemContainer);
				Overhead += Writing ? EmitHeader(itemContainer.Authenticator) : ConsumeHeader(itemContainer.Authenticator);
			}
			var itemDecorator = itemContainer.Decorator;
			var itemAuthenticator = itemContainer.Authenticator;

			var opLength = NextOperationLength ();

			if(Writing) {
				if(itemDecorator.BytesIn + opLength > item.ExternalLength) {
					// Final operation, or just prior to
					if(!itemContainer.Buffer.IsValueCreated) {
						// Redirect final ciphertext to buffer to account for possible expansion
						itemAuthenticator.ReassignBinding (itemContainer.Buffer.Value, 
							reset: false, finish: false);
					}
					int remaining = (int) (item.ExternalLength - itemDecorator.BytesIn);
					if(remaining > 0) {
						int iterIn = 0;
						while (remaining > 0) {
							int toRead = Math.Min (remaining, BufferSize);
							iterIn = item.StreamBinding.Read (Buffer, 0, toRead);
							if(iterIn < toRead) {
								throw new EndOfStreamException ();
							}
							itemDecorator.Write (Buffer, 0, iterIn); // writing into recently-lazy-inited buffer
							remaining -= iterIn;
						}
						itemDecorator.Close ();
					}
					int toWrite = (int) Math.Min (opLength, itemContainer.Buffer.Value.Length);
					itemContainer.Buffer.Value.ReadTo (PayloadStream, toWrite, true);
				} else {
					Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation", 
						"Item multiplexing operation length", opLength));
					itemDecorator.WriteExactlyFrom (item.StreamBinding, opLength);
				}
			} else {
				bool finalOp = false;
				if(itemDecorator.BytesIn + opLength > item.InternalLength) {
					// Final operation
					opLength = item.InternalLength - itemDecorator.BytesIn;
					finalOp = true;
				}
				Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation", 
					finalOp == true ? "Final item demultiplexing operation length" : "Item demultiplexing operation length", opLength));
				itemDecorator.ReadExactlyTo (item.StreamBinding, opLength, finalOp);
			}

			if ((Writing && itemDecorator.BytesIn == item.ExternalLength && itemContainer.Buffer.Value.Length == 0) ||
			   (!Writing && itemDecorator.BytesIn == item.InternalLength))
			{
				// Final stages of Encrypt-then-MAC authentication scheme
				byte[] encryptionConfig = item.Encryption.SerialiseDto ();
				// Authenticate the encryption configuration
				itemAuthenticator.Update (encryptionConfig, 0, encryptionConfig.Length);
				itemAuthenticator.Close ();
				if (Writing) {
					// Item is completely written out
					Overhead += EmitTrailer (itemAuthenticator);
					// Commit the MAC to item in payload manifest
					item.Authentication.VerifiedOutput = itemAuthenticator.Mac;
					// Commit the determined internal length to item in payload manifest
					item.InternalLength = itemDecorator.BytesOut;
				} else {
					// Verify the authenticity of the item ciphertext and configuration
					if (!itemAuthenticator.Mac.SequenceEqualConstantTime (item.Authentication.VerifiedOutput)) {
						// Verification failed!1
						throw new CiphertextAuthenticationException ("Payload item not authenticated.");
					}
				}
				// Mark the item as completed in the register
				ItemCompletionRegister [Index] = true;
				ItemsCompleted++;
				// Close the source/destination
				item.StreamBinding.Close ();
				// Release the item's resources (implicitly - no references remain)
				_activeItemResources.Remove (itemIdentifier);
				Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation", "[*** END OF ITEM",
					Index + " ***]"));
			}
		}

		/// <summary>
		/// If variable striping mode is enabled, advances the state of the selection CSPRNG, 
		/// and returns the output to be used as the length of the next operation. 
		/// Otherwise, fixed length is returned.
		/// </summary>
		/// <returns>Operation length to perform.</returns>
		private long NextOperationLength() {
			var opLen = _stripeMode == FabricStripeMode.VariableLength ? SelectionSource.Next (_minStripe, _maxStripe) : _maxStripe;
			Debug.Print (DebugUtility.CreateReportString ("FabricPayloadMux", "NextOperationLength", "Generated stripe length",
				opLen));
			return opLen;
		}
	}
#endif
}

