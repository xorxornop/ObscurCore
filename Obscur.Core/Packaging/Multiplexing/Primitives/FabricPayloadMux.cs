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
using Obscur.Core.Cryptography;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.Ciphers;
using Obscur.Core.DTO;
using PerfCopy;
using RingByteBuffer;

namespace Obscur.Core.Packaging.Multiplexing.Primitives
{
#if INCLUDE_FABRIC
    /// <summary>
    ///     Derived payload multiplexer implementing item layout in stripes of either
    ///     constant or PRNG-varied length.
    /// </summary>
    public sealed class FabricPayloadMux : SimplePayloadMux
    {
        /// <summary>
        ///     Minimum permissible stripe length.
        /// </summary>
        /// <remarks>
        ///     Must be constant within a given DTO version lifetime (<see cref="Athena.Packaging.PackageFormatVersion"/>).
        /// </remarks>
        public const int MinimumStripeLength = 8;

        /// <summary>
        ///     Maximum permissible stripe length.
        /// </summary>
        /// <remarks>
        ///     Must be constant within a given DTO version lifetime (<see cref="Athena.Packaging.PackageFormatVersion"/>).
        /// </remarks>
        public const int MaximumStripeLength = 32768; // 32 KB

        /// <summary>
        ///     Default stripe length.
        /// </summary>
        public const int DefaultFixedStripeLength = 512;

        /// <summary>
        ///     Used for <see cref="PayloadMuxEntropyScheme.Preallocation" /> scheme. Size in bytes.
        /// </summary>
        /// <remarks>
        ///     Must be constant within a given DTO version lifetime (<see cref="Athena.Packaging.PackageFormatVersion"/>).
        /// </remarks>
        internal const int StripeFieldMaximumSize = sizeof(UInt16);

        private readonly Dictionary<Guid, MuxItemResourceContainer> _activeItemResources =
            new Dictionary<Guid, MuxItemResourceContainer>();

        private readonly int _maxStripe;
        private readonly int _minStripe;
        private readonly FabricStripeMode _stripeMode;

        /// <summary>
        ///     Initializes a new instance of a payload multiplexer.
        /// </summary>
        /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
        /// <param name="multiplexedStream">
        ///     Stream being written to (destination; multiplexing) or read from (source;
        ///     demultiplexing).
        /// </param>
        /// <param name="payloadItems">Payload items to write.</param>
        /// <param name="itemPreKeys">Pre-keys for items (indexed by item identifiers).</param>
        /// <param name="config">Configuration of stream selection and stripe scheme.</param>
        /// <exception cref="ArgumentOutOfRangeException">Stripe size not within specification range.</exception>
        public FabricPayloadMux(bool writing, Stream multiplexedStream, IReadOnlyList<PayloadItem> payloadItems,
                                IReadOnlyDictionary<Guid, byte[]> itemPreKeys, PayloadConfiguration config)
            : base(writing, multiplexedStream, payloadItems, itemPreKeys, config)
        {
            var fabricConfig = config.SchemeConfiguration.DeserialiseDto<RangeConfiguration>();

            if (fabricConfig.Minimum < MinimumStripeLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Minimum stripe length is below specification minimum.");
            }
            if (fabricConfig.Maximum > MaximumStripeLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Maximum stripe length is above specification minimum.");
            }

            _minStripe = fabricConfig.Minimum;
            _maxStripe = fabricConfig.Maximum;
            _stripeMode = _minStripe == _maxStripe ? FabricStripeMode.FixedLength : FabricStripeMode.VariableLength;
        }


        /// <summary>
        ///     Create and bind Encrypt-then-MAC scheme components for an item.
        ///     Adds finished decorator (cipher/encryptor) and authenticator to mux item resource container.
        /// </summary>
        /// <param name="item">Item to prepare resources for.</param>
        private MuxItemResourceContainer CreateEtMSchemeResources(PayloadItem item)
        {
            CipherStream encryptor;
            MacStream authenticator;
            CreateEtMDecorator(item, out encryptor, out authenticator);
            var container = new MuxItemResourceContainer(encryptor, authenticator,
                _maxStripe + encryptor.OutputBufferSize);
            return container;
        }

        protected override void ExecuteOperation()
        {
            Debug.Assert(ItemCompletionRegister[Index] == false);

            PayloadItem item = PayloadItems[Index];
            Guid itemIdentifier = item.Identifier;

            bool skip = ItemSkipRegister != null && ItemSkipRegister.Contains(itemIdentifier);

            MuxItemResourceContainer itemContainer;
            bool activeResource = _activeItemResources.ContainsKey(itemIdentifier);

            if (activeResource) {
                itemContainer = _activeItemResources[itemIdentifier];
            } else {
                if (skip == false) {
                    itemContainer = CreateEtMSchemeResources(item);
                    if (Writing) {
                        EmitHeader(itemContainer.Authenticator);
                    } else {
                        ConsumeHeader(itemContainer.Authenticator);
                    }
                } else {
                    itemContainer = new MuxItemResourceContainer(null, null, null);
                }
                _activeItemResources.Add(itemIdentifier, itemContainer);
            }

            int opLength = NextOperationLength();

            if (skip == false) {
                CipherStream itemEncryptor = itemContainer.Encryptor;
                MacStream itemAuthenticator = itemContainer.Authenticator;

                if (Writing) {
                    // Writing/multiplexing
                    if (itemEncryptor.BytesIn + opLength < item.ExternalLength) {
                        // Normal operation
                        itemEncryptor.WriteExactly(item.StreamBinding, opLength);
                    } else {
                        // Final operation, or just prior to
                        if (itemContainer.Buffer.IsValueCreated == false) {
                            // Redirect final ciphertext to buffer to account for possible expansion
                            itemAuthenticator.ReassignBinding(itemContainer.Buffer.Value, false, finish: false);
                        }
                        var remaining = (int) (item.ExternalLength - itemEncryptor.BytesIn);
                        if (remaining > 0) {
                            while (remaining > 0) {
                                int toRead = Math.Min(remaining, BufferSize);
                                int iterIn = item.StreamBinding.Read(Buffer, 0, toRead);
                                if (iterIn < toRead) {
                                    throw new EndOfStreamException();
                                }
                                itemEncryptor.Write(Buffer, 0, iterIn); // Writing into recently-lazy-inited buffer
                                remaining -= iterIn;
                            }
                            itemEncryptor.Close();
                        }
                        var toWrite = (int) Math.Min(opLength, itemContainer.Buffer.Value.Length);
                        Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation",
                            "Multiplexing item: final stripe length", toWrite));

                        itemContainer.Buffer.Value.ReadTo(PayloadStream, toWrite);
                    }
                } else {
                    // Reading/demultiplexing
                    long readRemaining = item.InternalLength - itemEncryptor.BytesIn;
                    bool finalOp = false;
                    if (readRemaining <= opLength) {
                        // Final operation
                        opLength = (int) readRemaining;
                        finalOp = true;
                        Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation",
                            "Demultiplexing item: final stripe length", opLength));
                    }
                    itemEncryptor.ReadExactly(item.StreamBinding, opLength, finalOp);
                }

                if ((Writing && itemEncryptor.BytesIn >= item.ExternalLength && itemContainer.Buffer.Value.Length == 0) ||
                    (Writing == false && itemEncryptor.BytesIn >= item.InternalLength)) {
                    // Now that we're finished we need to do some extra things, then clean up
                    FinishItem(item, itemEncryptor, itemAuthenticator);
                }
            } else {
                // Skipping
                Debug.Assert(Writing == false, "Should not be skipping when writing!");

                if (itemContainer.SkippedLength == 0) {
                    // Start of item
                    PayloadStream.Seek(opLength, SeekOrigin.Current);
                    itemContainer.SkippedLength += opLength;
                } else if (itemContainer.SkippedLength + opLength >= item.InternalLength) {
                    int remainingToSkip = (int) (item.InternalLength - itemContainer.SkippedLength);
                    itemContainer.SkippedLength += remainingToSkip;
                    PayloadStream.Seek(remainingToSkip + GetTrailerLength(), SeekOrigin.Current);
                    // "Finish" item
                    _activeItemResources.Remove(item.Identifier);
                    // Mark the item as completed in the register
                    ItemCompletionRegister[Index] = true;
                    ItemsCompleted++;
                    Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation", "[*** SKIPPED ITEM",
                        Index + " ***]"));
                } else {
                    PayloadStream.Seek(opLength, SeekOrigin.Current);
                    itemContainer.SkippedLength += opLength;
                }
            }
        }

        /// <inheritdoc />
        protected override void FinishItem(PayloadItem item, CipherStream encryptor, MacStream authenticator)
        {
            if (Writing) {
                if (item.ExternalLength > 0 && encryptor.BytesIn != item.ExternalLength) {
                    throw new InvalidDataException("Length written is not equal to predefined item external length.");
                }
            } else {
                if (encryptor.BytesIn != item.InternalLength) {
                    throw new InvalidDataException("Length read is not equal to item internal length.");
                }
                if (encryptor.BytesOut != item.ExternalLength) {
                    throw new InvalidDataException("Demultiplexed and decrypted length is not equal to specified item external length.");
                }
                encryptor.Close();
            }

            if (Writing) {
                // Commit the determined internal length to item in payload manifest
                item.InternalLength = encryptor.BytesOut;
                EmitTrailer(authenticator);
            } else {
                ConsumeTrailer(authenticator);
            }

            // Final stages of Encrypt-then-MAC authentication scheme
            PayloadItem itemDto = item.CreateAuthenticatibleClone();
            byte[] itemDtoAuthBytes = itemDto.SerialiseDto();

            Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "FinishItem", "Item DTO length",
                itemDtoAuthBytes.Length));

            if (Writing) {
                authenticator.Update(itemDtoAuthBytes, 0, itemDtoAuthBytes.Length);
                authenticator.Close();
                // Commit the MAC to item in payload manifest
                item.AuthenticationVerifiedOutput = authenticator.Mac.DeepCopy();
            } else {
                authenticator.Update(itemDtoAuthBytes, 0, itemDtoAuthBytes.Length);
                authenticator.Close();
                // Verify the authenticity of the item ciphertext and configuration
                if (authenticator.Mac.SequenceEqual_ConstantTime(item.AuthenticationVerifiedOutput) == false) {
                    // Verification failed!
                    throw new CiphertextAuthenticationException("Payload item not authenticated.");
                }
            }


            // Release the item's resources (implicitly - no references remain)
            _activeItemResources.Remove(item.Identifier);

            // Mark the item as completed in the register
            ItemCompletionRegister[Index] = true;
            ItemsCompleted++;
            // Close the source/destination
            item.StreamBinding.Close();

            Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "FinishItem", "[*** END OF ITEM",
                Index + " ***]"));
        }

        /// <summary>
        ///     If variable striping mode is enabled, advances the state of the selection CSPRNG,
        ///     and returns the output to be used as the length of the next operation.
        ///     Otherwise, fixed length is returned.
        /// </summary>
        /// <returns>Operation length to perform.</returns>
        private int NextOperationLength()
        {
            int operationLength = _stripeMode == FabricStripeMode.VariableLength
                ? EntropySource.Next(_minStripe, _maxStripe)
                : _maxStripe;
            Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "NextOperationLength", "Generated stripe length value",
                operationLength));
            return operationLength;
        }

        #region Nested type: MuxItemResourceContainer

        private class MuxItemResourceContainer
        {
            public MuxItemResourceContainer(CipherStream encryptor, MacStream authenticator, int? bufferCapacity)
            {
                Encryptor = encryptor;
                Authenticator = authenticator;
                if (bufferCapacity != null) {
                    Buffer = new Lazy<RingBufferStream>(() => new RingBufferStream(bufferCapacity.Value, false));
                } else {
                    SkippedLength = 0;
                }
            }

            public CipherStream Encryptor { get; private set; }
            public MacStream Authenticator { get; private set; }
            public Lazy<RingBufferStream> Buffer { get; private set; }
            public long? SkippedLength { get; set; }
        }

        #endregion
    }
#endif
}
