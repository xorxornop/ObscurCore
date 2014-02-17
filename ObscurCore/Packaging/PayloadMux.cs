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
using ObscurCore.Cryptography.Authentication;
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
		protected readonly bool Writing;
		protected int Index;
		protected int ItemsCompleted;
		protected readonly Stream PayloadStream;
		protected IReadOnlyList<PayloadItem> PayloadItems;
		protected IReadOnlyDictionary<Guid, byte[]> PayloadItemPreKeys;
		protected readonly bool[] ItemCompletionRegister;

		public PayloadMux (bool writing, Stream payloadStream, IReadOnlyList<PayloadItem> payloadItems, 
			IReadOnlyDictionary<Guid, byte[]> itemPreKeys)
		{
			if (payloadStream == null)
				throw new ArgumentNullException ("payloadStream");
			if (payloadItems == null)
				throw new ArgumentNullException ("payloadItems");
			if (itemPreKeys == null)
				throw new ArgumentNullException ("itemPreKeys");

			this.Writing = writing;
			this.PayloadStream = payloadStream;
			this.PayloadItems = payloadItems;

			ItemCompletionRegister = new bool[PayloadItems.Count];
		}

		protected void CreateEtMSchemeStreams(PayloadItem item, out DecoratingStream decorator, out MacStream authenticator) {
			byte[] encryptionKey, authenticationKey;
			if (item.EncryptionKey.IsNullOrZeroLength() == false && item.AuthenticationKey.IsNullOrZeroLength() == false) {
				encryptionKey = item.EncryptionKey;
				authenticationKey = item.AuthenticationKey;
			} else if (PayloadItemPreKeys.ContainsKey(item.Identifier)) {
				if (item.Authentication.KeySizeBits.HasValue == false) {
					throw new ConfigurationInvalidException ("Payload item authentication configuration is missing size specification of MAC key.");
				}
				KeyStretchingUtility.DeriveWorkingKeys (PayloadItemPreKeys [item.Identifier], item.Encryption.KeySizeBits / 8, 
					item.Authentication.KeySizeBits.Value / 8, item.KeyDerivation, out encryptionKey, out authenticationKey);
			} else {
				throw new ItemKeyMissingException (item);
			}

			authenticator = new MacStream (PayloadStream, Writing, item.Authentication, 
				authenticationKey, closeOnDispose : false);
			decorator = new SymmetricCipherStream (authenticator, Writing, item.Encryption, 
				encryptionKey, closeOnDispose:false);
		}

		/// <summary>
		/// Executes multiplexing operations until source(s) are exhausted.
		/// </summary>
		public void Execute() {
			while (ItemsCompleted != PayloadItems.Count) {
				ExecuteOperation();
				do {
					NextSource();
					Debug.Print(DebugUtility.CreateReportString("PayloadMux", "Execute", "Generated index",
						Index));
				} while (ItemCompletionRegister[Index] == true && ItemsCompleted != PayloadItems.Count);
				Debug.Print(DebugUtility.CreateReportString("PayloadMux", "Execute", "Selected stream",
					Index));
			}
		}

		/// <summary>
		/// Executes a single mux/demux operation.
		/// </summary>
		protected abstract void ExecuteOperation();

		/// <summary>
		/// Determine the index of the next stream to use in an I/O operation (whether to completion or just a buffer-full).
		/// </summary>
		/// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
		/// <returns>The next stream index.</returns>
		protected virtual void NextSource() {
			Index++;
			if (Index == PayloadItems.Count) Index = 0;
		}
	}
}

