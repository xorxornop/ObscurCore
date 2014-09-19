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
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.DTO;

namespace ObscurCore.Packaging.Multiplexing
{
    /// <summary>
    ///     Multiplexer for stream sources/sinks. Mixes reads/writes among an arbitrary number of streams.
    /// </summary>
    /// <remarks>
    ///     Supports extensions for control of operation size (partial/split item writes), ordering,
    ///     and item headers and trailers. Records I/O history itemwise and total.
    /// </remarks>
    public abstract class PayloadMux
    {
        protected readonly bool[] ItemCompletionRegister;
        protected readonly ICollection<Guid> ItemSkipRegister;
        protected readonly Stream PayloadStream;
        protected readonly bool Writing;
        protected int Index;
        protected int ItemsCompleted;
        protected IReadOnlyDictionary<Guid, byte[]> PayloadItemPreKeys;
        protected IReadOnlyList<PayloadItem> PayloadItems;

        protected PayloadMux(bool writing, Stream payloadStream, IReadOnlyList<PayloadItem> payloadItems,
                             IReadOnlyDictionary<Guid, byte[]> itemPreKeys, ICollection<Guid> skips = null)
        {
            if (payloadStream == null) {
                throw new ArgumentNullException("payloadStream");
            }
            if (payloadItems == null) {
                throw new ArgumentNullException("payloadItems");
            }
            if (itemPreKeys == null) {
                throw new ArgumentNullException("itemPreKeys");
            }

            Writing = writing;
            PayloadStream = payloadStream;
            PayloadItems = payloadItems;
            PayloadItemPreKeys = itemPreKeys;
            ItemSkipRegister = writing ? null : skips;

            ItemCompletionRegister = new bool[PayloadItems.Count];
        }

        /// <summary>
        ///     Create decorator streams implementing the Encrypt-then-MAC scheme (CipherStream bound to a MacStream).
        /// </summary>
        /// <param name="item"></param>
        /// <param name="encryptor"></param>
        /// <param name="authenticator"></param>
        protected void CreateEtMDecorator(PayloadItem item, out CipherStream encryptor, out MacStream authenticator)
        {
            byte[] encryptionKey, authenticationKey;
            if (item.SymmetricCipherKey.IsNullOrZeroLength() == false && item.AuthenticationKey.IsNullOrZeroLength() == false) {
                encryptionKey = item.SymmetricCipherKey;
                authenticationKey = item.AuthenticationKey;
            } else if (PayloadItemPreKeys.ContainsKey(item.Identifier)) {
                if (item.Authentication.KeySizeBits.HasValue == false) {
                    throw new ConfigurationInvalidException(
                        "Payload item authentication configuration is missing size specification of MAC key.");
                }
                KeyStretchingUtility.DeriveWorkingKeys(PayloadItemPreKeys[item.Identifier],
                    item.SymmetricCipher.KeySizeBits / 8,
                    item.Authentication.KeySizeBits.Value / 8, item.KeyDerivation, out encryptionKey,
                    out authenticationKey);
            } else {
                throw new ItemKeyMissingException(item);
            }

            authenticator = new MacStream(PayloadStream, Writing, item.Authentication,
                authenticationKey, false);
            encryptor = new CipherStream(authenticator, Writing, item.SymmetricCipher,
                encryptionKey, false);
        }

        /// <summary>
        ///     Executes multiplexing operations until source(s) are exhausted.
        /// </summary>
        public void Execute()
        {
            while (ItemsCompleted < PayloadItems.Count) {
                ExecuteOperation();
                while (ItemsCompleted < PayloadItems.Count && ItemCompletionRegister[Index]) {
                    NextSource();
                    Debug.Print(DebugUtility.CreateReportString("PayloadMux", "Execute", "Generated index",
                        Index));
                }
                Debug.Print(DebugUtility.CreateReportString("PayloadMux", "Execute", "Selected stream",
                    Index));
            }
        }

        /// <summary>
        ///     Executes a single mux/demux operation.
        /// </summary>
        protected abstract void ExecuteOperation();

        protected abstract void FinishItem(PayloadItem item, DecoratingStream decorator, MacStream authenticator);

        /// <summary>
        ///     Determine the index of the next stream to use in an I/O operation
        ///     (whether to completion or otherwise, depending on implementation).
        /// </summary>
        /// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
        /// <returns>The next stream index.</returns>
        protected virtual void NextSource()
        {
            Index++;
            if (Index == PayloadItems.Count) {
                Index = 0;
            }
        }
    }
}
