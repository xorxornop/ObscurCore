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
using System.Linq;

using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
	/// <summary>
	/// Multiplexer for stream sources/sinks. Mixes reads/writes among an arbitrary number of streams.
	/// </summary>
	/// <remarks>
	/// Supports extensions for control of operation size (partial/split item writes), ordering, 
	/// and item headers & trailers. Records I/O history itemwise and total.
	/// </remarks>
	public abstract class PayloadMux
	{
		private bool _writing;

		protected int Index;
		protected Manifest PayloadManifest;
		protected readonly Stream PayloadStream;

		protected Dictionary<Guid, DecoratingStream> ItemStreamDecorators = new Dictionary<Guid, DecoratingStream>();
		protected Dictionary<Guid, MacStream> ItemStreamMacs = new Dictionary<Guid, MacStream>();
		protected readonly long[] AccumulatorIn, AccumulatorOut;

		public bool Writing { 
			get { return _writing; } 
		}

		public int CurrentIndex { 
			get { return Index; }
		}

		public int ItemCount {
			get { return PayloadManifest.PayloadItems.Count; }
		}

		public int ItemsCompleted { get; protected set; }

		public int Overhead { get; protected set; }

		public long TotalSourceIO {
			get { return GetTotalIO(true); }
		}

		public long TotalDestinationIO {
			get { return GetTotalIO(false); }
		}


		public PayloadMux (bool writing, Stream payloadStream, Manifest payloadManifest)
		{
			this._writing = writing;
			this.PayloadStream = payloadStream;
			this.PayloadManifest = payloadManifest;

			AccumulatorIn = new long[PayloadManifest.PayloadItems.Count];
			AccumulatorOut = new long[PayloadManifest.PayloadItems.Count];
		}


		/// <summary>
		/// Create and bind Encrypt-then-MAC scheme components for an item. 
		/// Adds finished encrypter and MACer to ItemStreamDecorators 
		/// and ItemStreamMacs, respectively.
		/// </summary>
		/// <param name="item">Item.</param>
		/// <param name="binding">Binding.</param>
		private void CreateAndBindEtMSchemeDecorators(PayloadItem item) {
			MacStream authenticator = new MacStream (PayloadStream, _writing, item.EncryptionAuthentication, 
				null, closeOnDispose:false);
			DecoratingStream decorator = new SymmetricCryptoStream (authenticator, _writing, item.Encryption, 
				null, closeOnDispose:false);
			var identifier = item.Identifier;
			ItemStreamMacs.Add (identifier, authenticator);
			ItemStreamDecorators.Add (identifier, decorator);
		}

		#region Core methods

		/// <summary>
		/// Executes the single new.
		/// </summary>
		public void ExecuteSingle() {
			var item = PayloadManifest.PayloadItems[Index];
			var itemIdentifier = item.Identifier;

			if(!ItemStreamDecorators.ContainsKey(itemIdentifier)) {
				CreateAndBindEtMSchemeDecorators (PayloadManifest.PayloadItems [Index]);
			}

			DecoratingStream itemDecorator = ItemStreamDecorators[itemIdentifier];
			MacStream itemAuthenticator = ItemStreamMacs[itemIdentifier];

			// Is it the start of the item?
			if (AccumulatorIn[Index] == 0) {
				if (Writing) {
					Overhead += EmitHeader();
				} else {
					Overhead += ConsumeHeader();
				}
			}

			long referenceLength = Writing ? 
				PayloadManifest.PayloadItems [Index].ExternalLength : PayloadManifest.PayloadItems [Index].InternalLength;

			long operationLength = NextOperationLength ();
			if(operationLength + AccumulatorIn[Index] > referenceLength) {
				operationLength = referenceLength - AccumulatorIn [Index];
			}
			Debug.Print(DebugUtility.CreateReportString("PayloadMux", "ExecuteSingle", "Operation length",
				operationLength));

			// Perform the operation
			if(Writing) {
				AccumulatorIn[Index] += itemDecorator.WriteExactlyFrom (item.StreamBinding, operationLength);
				AccumulatorOut[Index] += operationLength;
			} else {
				AccumulatorOut[Index] += itemAuthenticator.ReadExactlyTo (item.StreamBinding, operationLength);
				AccumulatorIn[Index] += operationLength;
			}

			// Check if the item is complete
			long remaining = referenceLength - AccumulatorIn[Index];
			if (remaining <= 0) {
				if (remaining < 0) {
					throw new IOException ("Overrun of " + Math.Abs(remaining) 
						+ " bytes. Probable decorator stack malfunction.");
				}

				// Item is finished, we need to do some things.
				Overhead += Writing ? EmitTrailer() : ConsumeTrailer();
				// Finish the encryption/decryption operation
				itemDecorator.Close ();
				// Final stage of Encrypt-then-MAC scheme
				byte[] encryptionConfig = item.Encryption.SerialiseDto ();
				// Authenticate the encryption configuration
				itemAuthenticator.Update (encryptionConfig, 0, encryptionConfig.Length);
				itemAuthenticator.Close ();

				if(_writing) {
					// Commit the MAC to item in payload manifest
					item.EncryptionAuthentication.VerifiedOutput = itemAuthenticator.Mac;
					// Commit the determined internal length to item in payload manifest
					item.InternalLength = AccumulatorOut[Index];
				} else {
					// Verify the authenticity of the item ciphertext and configuration
					if(!itemAuthenticator.Mac.SequenceEqualConstantTime
						(item.EncryptionAuthentication.VerifiedOutput)) 
					{
						// Verification failed!
						throw new CiphertextAuthenticationException ();
					}
					Debug.Print (DebugUtility.CreateReportString ("PayloadMux", "ExecuteSingle", 
						"Authentication successful for item", Index));

					if(AccumulatorOut[Index] != item.ExternalLength) {
						throw new InvalidDataException ("Mismatch between stated item external length and actual output length.");
					}
				}

				// Mark the item as completed in the accumulators
				AccumulatorIn[Index] *= -1;
				AccumulatorOut[Index] *= 1;
				ItemsCompleted++;

				// Close the source/destination
				item.StreamBinding.Close();
				Debug.Print(DebugUtility.CreateReportString("PayloadMux", "ExecuteSingle", "[*** END OF ITEM",
					CurrentIndex + " ***]"));
			}
		}

		/// <summary>
		/// Executes multiplexing operations until all sources are exhausted.
		/// </summary>
		public void ExecuteAll() {
			do {
				ExecuteSingle();
			} while (AdvanceSource());
		}

		/// <summary>
		/// Advances the current source stream until an active stream is selected. Returns false if all exhausted.
		/// </summary>
		/// <returns><c>true</c>, if next stream was available, <c>false</c> if all exhausted.</returns>
		public bool AdvanceSource() {
			if (ItemsCompleted == PayloadManifest.PayloadItems.Count) {
				return false;
			}
			do {
				NextSource();
				Debug.Print(DebugUtility.CreateReportString("PayloadMux", "AdvanceSource", "Generated index",
					Index));
			} while (AccumulatorIn[Index] < 0); // If accumulator # is under 0 (-ve), item is finished.
			Debug.Print(DebugUtility.CreateReportString("PayloadMux", "AdvanceSource", "Selected stream",
				Index));
			return true;
		}

		#endregion


		#region Extensible

		/// <summary>
		/// Determine the index of the next stream to use in an I/O operation (whether to completion or just a buffer-full).
		/// </summary>
		/// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
		/// <returns>The next stream index.</returns>
		protected virtual void NextSource() {
			Index++;
			if (Index == PayloadManifest.PayloadItems.Count) Index = 0;
		}

		/// <summary>
		/// Returns the length of the next I/O operation to take place. 
		/// Depending on implementation in derived classes, may advance state also.
		/// </summary>
		/// <remarks>May be overriden in a derived class to provide for advanced operation length selection logic.</remarks>
		/// <returns>The next operation length.</returns>
		protected virtual long NextOperationLength() {
			return Writing ? 
				PayloadManifest.PayloadItems[Index].ExternalLength : PayloadManifest.PayloadItems[Index].InternalLength;
		}

		protected virtual int EmitHeader() {
			// Unused in this version
			return 0;
		}

		protected virtual int EmitTrailer() {
			// Unused in this version
			return 0;
		}

		protected virtual int ConsumeHeader() {
			// Unused in this version
			// Could throw an exception in an implementation where a header must be present
			return 0;
		}

		protected virtual int ConsumeTrailer() {
			// Unused in this version
			// Could throw an exception in an implementation where a trailer must be present
			return 0;
		}

		#endregion

		private long GetTotalIO(bool source) {
			var collection = (Writing == source) ? AccumulatorIn : AccumulatorOut;
			var sum = collection.Sum(num => Math.Abs(num));
			return sum + Overhead;
		}
	}
}

