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

#define PRINT_DTO_LENGTH

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;
using RingByteBuffer;

namespace ObscurCore.Packaging.Multiplexing.Primitives
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
        public const int MinimumStripeLength = 8;

        /// <summary>
        ///     Maximum permissible stripe length.
        /// </summary>
        public const int MaximumStripeLength = 32768; // 32 KB

        /// <summary>
        ///     Default stripe length.
        /// </summary>
        public const int DefaultFixedStripeLength = 512;

        /// <summary>
        ///     Used for <see cref="PayloadMuxEntropyScheme.Preallocation"/> scheme. Size in bytes.
        /// </summary>
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
        public FabricPayloadMux(bool writing, Stream multiplexedStream, IReadOnlyList<PayloadItem> payloadItems,
                                IReadOnlyDictionary<Guid, byte[]> itemPreKeys, PayloadConfiguration config)
            : base(writing, multiplexedStream, payloadItems, itemPreKeys, config)
        {
            var fabricConfig = config.SchemeConfiguration.DeserialiseDto<RangeConfiguration>();

            if (fabricConfig.Minimum < MinimumStripeLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Minimum stripe length is set below specification minimum.");
            }
            if (fabricConfig.Maximum > MaximumStripeLength) {
                throw new ArgumentOutOfRangeException("config",
                    "Maximum stripe length is set above specification minimum.");
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
                _maxStripe + encryptor.BufferSizeRequirement);
            return container;
        }

        protected override void ExecuteOperation()
        {
            PayloadItem item = PayloadItems[Index];
            Guid itemIdentifier = item.Identifier;
            MuxItemResourceContainer itemContainer;

            if (_activeItemResources.ContainsKey(itemIdentifier)) {
                itemContainer = _activeItemResources[itemIdentifier];
            } else {
                itemContainer = CreateEtMSchemeResources(item);
                _activeItemResources.Add(itemIdentifier, itemContainer);
                if (Writing) {
                    EmitHeader(itemContainer.Authenticator);
                } else {
                    ConsumeHeader(itemContainer.Authenticator);
                }
            }

            CipherStream itemEncryptor = itemContainer.Encryptor;
            MacStream itemAuthenticator = itemContainer.Authenticator;

            long opLength = NextOperationLength();

            if (Writing) {
                if (itemEncryptor.BytesIn + opLength < item.ExternalLength) {
                    // Normal operation
                    Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation",
                        "Item multiplexing operation length", opLength));
                    itemEncryptor.WriteExactlyFrom(item.StreamBinding, opLength);
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
                    itemContainer.Buffer.Value.ReadTo(PayloadStream, toWrite);
                }
            } else {
                bool finalOp = false;
                if (itemEncryptor.BytesIn + opLength > item.InternalLength) {
                    // Final operation
                    opLength = item.InternalLength - itemEncryptor.BytesIn;
                    finalOp = true;
                }
                Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation",
                    finalOp
                        ? "Final item demultiplexing operation length"
                        : "Item demultiplexing operation length", opLength));
                itemEncryptor.ReadExactlyTo(item.StreamBinding, opLength, finalOp);
            }

            if ((Writing && itemEncryptor.BytesIn == item.ExternalLength && itemContainer.Buffer.Value.Length == 0) ||
                (Writing == false && itemEncryptor.BytesIn == item.InternalLength)) {
                // Now that we're finished we need to do some extra things, then clean up
                FinishItem(item, itemEncryptor, itemAuthenticator);
            }
        }

        protected override void FinishItem(PayloadItem item, DecoratingStream decorator, MacStream authenticator)
        {
            if (Writing) {
                EmitTrailer(authenticator);
                // Commit the MAC to item in payload manifest
                item.AuthenticationVerifiedOutput = authenticator.Mac.DeepCopy();
                // Commit the determined internal length to item in payload manifest
                item.InternalLength = decorator.BytesOut;
            } else {
                ConsumeTrailer(authenticator);
                // Verify the authenticity of the item ciphertext and configuration
                if (authenticator.Mac.SequenceEqualConstantTime(item.AuthenticationVerifiedOutput) == false) {
                    // Verification failed!1
                    throw new CiphertextAuthenticationException("Payload item not authenticated.");
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

            // Mark the item as completed in the register
            ItemCompletionRegister[Index] = true;
            ItemsCompleted++;
            // Close the source/destination
            item.StreamBinding.Close();
            // Release the item's resources (implicitly - no references remain)
            _activeItemResources.Remove(item.Identifier);
            Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation", "[*** END OF ITEM",
                Index + " ***]"));
        }

        /// <summary>
        ///     If variable striping mode is enabled, advances the state of the selection CSPRNG,
        ///     and returns the output to be used as the length of the next operation.
        ///     Otherwise, fixed length is returned.
        /// </summary>
        /// <returns>Operation length to perform.</returns>
        private long NextOperationLength()
        {
            int operationLength = _stripeMode == FabricStripeMode.VariableLength
                    ? EntropySource.Next(_minStripe, _maxStripe)
                    : _maxStripe;

            Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "NextOperationLength",
                "Stripe length",
                operationLength));
            return operationLength;
        }

        #region Nested type: MuxItemResourceContainer

        private class MuxItemResourceContainer
        {
            public MuxItemResourceContainer(CipherStream encryptor, MacStream authenticator, int bufferCapacity)
            {
                this.Encryptor = encryptor;
                this.Authenticator = authenticator;
                this.Buffer = new Lazy<RingBufferStream>(() => new RingBufferStream(bufferCapacity, false));
            }

            public CipherStream Encryptor { get; private set; }
            public MacStream Authenticator { get; private set; }
            public Lazy<RingBufferStream> Buffer { get; private set; }
        }

        #endregion
    }
#endif
}
