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

// Controls whether, when debugging, the length of an item's DTO object is reported when authenticating it.
#define PRINT_DTO_LENGTH

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;
using ObscurCore.Packaging.Multiplexing.Entropy;

namespace ObscurCore.Packaging.Multiplexing.Primitives
{
    /// <summary>
    ///     Payload multiplexer implementing stream selection order by CSPRNG.
    /// </summary>
    public class SimplePayloadMux : PayloadMux
    {
        /// <summary>
        ///     Size of the internal buffer to use for multiplexing/demultiplexing I/O.
        /// </summary>
        protected const int BufferSize = 4096;

        /// <summary>
        ///     Used for <see cref="PayloadMuxEntropyScheme.Preallocation" /> scheme. Size in bytes.
        /// </summary>
        protected internal const int ItemFieldMaximumSize = sizeof(UInt16);

        /// <summary>
        ///     Internal buffer to use for multiplexing/demultiplexing I/O.
        /// </summary>
        protected readonly byte[] Buffer = new byte[BufferSize];

        /// <summary>
        ///     Entropy source for stream selection and other tasks (depending on implementation).
        /// </summary>
        protected MuxEntropySourceFacade EntropySource;

        private PayloadConfiguration _payloadConfigDto;

        /// <summary>
        ///     Initializes a new instance of a payload multiplexer.
        /// </summary>
        /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream (payload); otherwise, reading.</param>
        /// <param name="multiplexedStream">
        ///     Stream being written to (destination; multiplexing) or read from (source;
        ///     demultiplexing).
        /// </param>
        /// <param name="payloadItems">Payload items to write.</param>
        /// <param name="itemPreKeys">Pre-keys for items (indexed by item identifiers).</param>
        /// <param name="config">Configuration of stream selection.</param>
        public SimplePayloadMux(bool writing, Stream multiplexedStream, IReadOnlyList<PayloadItem> payloadItems,
                                IReadOnlyDictionary<Guid, byte[]> itemPreKeys, PayloadConfiguration config)
            : base(writing, multiplexedStream, payloadItems, itemPreKeys)
        {
            if (config == null) {
                throw new ArgumentNullException("config");
            }

            EntropySource = new MuxEntropySourceFacade(writing, config);
            _payloadConfigDto = config;

            NextSource();
        }

        /// <summary>
        ///     How many bytes written/read not constituting
        ///     item data emitted/consumed by their decorators.
        /// </summary>
        public int Overhead { get; protected set; }

        protected override void ExecuteOperation()
        {
            PayloadItem item = PayloadItems[Index];

            bool skip = ItemSkipRegister != null && ItemSkipRegister.Contains(item.Identifier);

            if (skip == false) {
                CipherStream itemEncryptor;
                MacStream itemAuthenticator;
                CreateEtMDecorator(item, out itemEncryptor, out itemAuthenticator);

                if (Writing) {
                    EmitHeader(itemAuthenticator);
                } else {
                    ConsumeHeader(itemAuthenticator);
                }

                if (Writing) {
                    int iterIn;
                    do {
                        iterIn = item.StreamBinding.Read(Buffer, 0, BufferSize);
                        itemEncryptor.Write(Buffer, 0, iterIn);
                    } while (iterIn > 0);
                } else {
                    itemEncryptor.ReadExactlyTo(item.StreamBinding, item.InternalLength, true);
                }

                FinishItem(item, itemEncryptor, itemAuthenticator);

                // Close the source/destination
                item.StreamBinding.Close();
            } else {
                long skipLength = GetHeaderLength() + item.InternalLength + GetTrailerLength();
                PayloadStream.Seek(skipLength, SeekOrigin.Current);
            }

            // Mark the item as completed in the register
            ItemCompletionRegister[Index] = true;
            ItemsCompleted++;

            Debug.Print(DebugUtility.CreateReportString("SimplePayloadMux", "ExecuteOperation",
                skip ? "[*** SKIPPED ITEM" : "[*** END OF ITEM",
                String.Format("{0} ({1}) ***]", Index, item.Identifier)));
        }

        /// <summary>
        ///     Close the item decorator, check lengths, authenticate the item (emit or verify),
        ///     and if writing, commit the authentication value to the payload item DTO.
        /// </summary>
        /// <param name="item">Payload item to finish.</param>
        /// <param name="decorator">Item decorator.</param>
        /// <param name="authenticator">Item authenticator.</param>
        protected override void FinishItem(PayloadItem item, DecoratingStream decorator, MacStream authenticator)
        {
            decorator.Close();

            if (Writing) {
                EmitTrailer(authenticator);
            } else {
                ConsumeTrailer(authenticator);
            }

            // Length checks & commits
            if (Writing) {
                // Check if pre-stated length matches what was actually written
                if (item.ExternalLength > 0 && decorator.BytesIn != item.ExternalLength) {
                    throw new InvalidDataException(
                        "Mismatch between stated item external length and actual input length.");
                }
                // Commit the determined internal length to item in payload manifest
                item.InternalLength = decorator.BytesOut;
            } else {
                if (decorator.BytesIn != item.InternalLength) {
                    throw new InvalidOperationException("Probable decorator stack malfunction.");
                }
                if (decorator.BytesOut != item.ExternalLength) {
                    throw new InvalidDataException(
                        "Mismatch between stated item external length and actual output length.");
                }
            }

            // Final stages of Encrypt-then-MAC authentication scheme
            PayloadItem itemDto = item.CreateAuthenticatibleClone();
            byte[] itemDtoAuthBytes = itemDto.SerialiseDto();
#if PRINT_DTO_LENGTH
            Debug.Print(DebugUtility.CreateReportString("SimplePayloadMux", "FinishItem", "Payload item DTO length",
                itemDtoAuthBytes.Length));
#endif
            authenticator.Update(itemDtoAuthBytes, 0, itemDtoAuthBytes.Length);
            authenticator.Close();

            // Authentication
            if (Writing) {
                // Commit the MAC to item in payload manifest
                item.AuthenticationVerifiedOutput = authenticator.Mac.DeepCopy();
            } else {
                // Verify the authenticity of the item ciphertext and configuration
                if (authenticator.Mac.SequenceEqualConstantTime(item.AuthenticationVerifiedOutput) == false) {
                    // Verification failed!
                    throw new CiphertextAuthenticationException("Payload item not authenticated.");
                }
            }
        }

        /// <summary>
        ///     Advances and returns the index of the next stream to use in an I/O operation (whether to completion or just a
        ///     buffer-full).
        /// </summary>
        /// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
        /// <returns>The next stream index.</returns>
        protected override sealed void NextSource()
        {
            Index = EntropySource.NextPositive(0, PayloadItems.Count - 1);
            Debug.Print(DebugUtility.CreateReportString("SimplePayloadMux", "NextSource", "Index",
                Index));
        }

        #region Extensible methods

        /// <summary>
        ///     Get the length of a header of the current item.
        /// </summary>
        /// <returns>Length of the header.</returns>
        protected virtual int GetHeaderLength()
        {
            // Unused in this version
            return 0;
        }

        /// <summary>
        ///     Generate and write an item header into the payload stream.
        /// </summary>
        /// <param name="authenticator">
        ///     Authenticator for the item, if header is to be authenticated.
        /// </param>
        protected virtual void EmitHeader(MacStream authenticator)
        {
            // Unused in this version
        }

        /// <summary>
        ///     Read an item header from the payload stream.
        /// </summary>
        /// <param name="authenticator">
        ///     Authenticator for the item, if header is to be authenticated.
        /// </param>
        protected virtual void ConsumeHeader(MacStream authenticator)
        {
            // Unused in this version
            // Could throw an exception in an implementation where a header must be present
        }

        /// <summary>
        ///     Get the length of a trailer of the current item.
        /// </summary>
        /// <returns>Length of the trailer.</returns>
        protected virtual int GetTrailerLength()
        {
            // Unused in this version
            return 0;
        }

        /// <summary>
        ///     Generate and write an item trailer into the payload stream.
        /// </summary>
        /// <param name="authenticator">
        ///     Authenticator for the item, if trailer is to be authenticated.
        /// </param>
        protected virtual void EmitTrailer(MacStream authenticator)
        {
            // Unused in this version
        }

        /// <summary>
        ///     Read an item trailer from the payload stream.
        /// </summary>
        /// <param name="authenticator">
        ///     Authenticator for the item, if trailer is to be authenticated.
        /// </param>
        protected virtual void ConsumeTrailer(MacStream authenticator)
        {
            // Unused in this version
            // Could throw an exception in an implementation where a trailer must be present
        }

        #endregion
    }
}
