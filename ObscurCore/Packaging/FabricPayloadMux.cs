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
#if (INCLUDE_FABRIC)
    /// <summary>
    /// Derived payload multiplexer implementing item layout in stripes of either 
    /// constant or PRNG-varied length.
    /// </summary>
    public sealed class FabricPayloadMux : SimplePayloadMux
    {
        public const int MinimumStripeLength = 8,
            MaximumStripeLength = 32768,
            DefaultFixedStripeLength = 512;

        private readonly FabricStripeMode _stripeMode;
        private readonly int _minStripe, _maxStripe;

        private readonly Dictionary<Guid, MuxItemResourceContainer> _activeItemResources =
            new Dictionary<Guid, MuxItemResourceContainer>();

        private class MuxItemResourceContainer
        {
            public MuxItemResourceContainer(DecoratingStream decorator, MacStream authenticator, int bufferCapacity)
            {
                this.Decorator = decorator;
                this.Authenticator = authenticator;
                this.Buffer = new Lazy<RingBufferStream>(() => new RingBufferStream(bufferCapacity, false));
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
        public FabricPayloadMux(bool writing, Stream multiplexedStream, IReadOnlyList<PayloadItem> payloadItems,
            IReadOnlyDictionary<Guid, byte[]> itemPreKeys, IPayloadConfiguration config)
            : base(writing, multiplexedStream, payloadItems, itemPreKeys, config)
        {
            var fabricConfig =
                StratCom.DeserialiseDataTransferObject<PayloadSchemeConfiguration>(config.SchemeConfiguration);
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
        /// Create and bind Encrypt-then-MAC scheme components for an item. 
        /// Adds finished decorator (cipher/encryptor) and authenticator to mux item resource container.
        /// </summary>
        /// <param name="item">Item to prepare resources for.</param>
        private MuxItemResourceContainer CreateEtMSchemeResources(PayloadItem item)
        {
            DecoratingStream decorator;
            MacStream authenticator;
            CreateEtMDecorator(item, out decorator, out authenticator);
            var container = new MuxItemResourceContainer(decorator, authenticator,
                _maxStripe + decorator.BufferSizeRequirement);
            return container;
        }

        protected override void ExecuteOperation()
        {
            var item = PayloadItems[Index];
            var itemIdentifier = item.Identifier;
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

            var itemDecorator = itemContainer.Decorator;
            var itemAuthenticator = itemContainer.Authenticator;

            var opLength = NextOperationLength();

            if (Writing) {
                if (itemDecorator.BytesIn + opLength > item.ExternalLength) {
                    // Final operation, or just prior to
                    if (itemContainer.Buffer.IsValueCreated == false) {
                        // Redirect final ciphertext to buffer to account for possible expansion
                        itemAuthenticator.ReassignBinding(itemContainer.Buffer.Value, reset: false, finish: false);
                    }
                    var remaining = (int) (item.ExternalLength - itemDecorator.BytesIn);
                    if (remaining > 0) {
                        while (remaining > 0) {
                            var toRead = Math.Min(remaining, BufferSize);
                            var iterIn = item.StreamBinding.Read(Buffer, 0, toRead);
                            if (iterIn < toRead) {
                                throw new EndOfStreamException();
                            }
                            itemDecorator.Write(Buffer, 0, iterIn); // Writing into recently-lazy-inited buffer
                            remaining -= iterIn;
                        }
                        itemDecorator.Close();
                    }
                    var toWrite = (int) Math.Min(opLength, itemContainer.Buffer.Value.Length);
                    itemContainer.Buffer.Value.ReadTo(PayloadStream, toWrite, true);
                } else {
                    Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation",
                        "Item multiplexing operation length", opLength));
                    itemDecorator.WriteExactlyFrom(item.StreamBinding, opLength);
                }
            } else {
                var finalOp = false;
                if (itemDecorator.BytesIn + opLength > item.InternalLength) {
                    // Final operation
                    opLength = item.InternalLength - itemDecorator.BytesIn;
                    finalOp = true;
                }
                Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "ExecuteOperation",
                    finalOp == true
                        ? "Final item demultiplexing operation length"
                        : "Item demultiplexing operation length", opLength));
                itemDecorator.ReadExactlyTo(item.StreamBinding, opLength, finalOp);
            }

            if ((Writing && itemDecorator.BytesIn == item.ExternalLength && itemContainer.Buffer.Value.Length == 0) ||
                (!Writing && itemDecorator.BytesIn == item.InternalLength)) {
                // Now that we're finished we need to do some extra things, then clean up
                FinishItem(item, itemDecorator, itemAuthenticator);
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
            byte[] itemDtoAuthBytes = item.CreateAuthenticatibleClone().SerialiseDto();
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
        /// If variable striping mode is enabled, advances the state of the selection CSPRNG, 
        /// and returns the output to be used as the length of the next operation. 
        /// Otherwise, fixed length is returned.
        /// </summary>
        /// <returns>Operation length to perform.</returns>
        private long NextOperationLength()
        {
            var opLen = _stripeMode == FabricStripeMode.VariableLength
                ? SelectionSource.Next(_minStripe, _maxStripe + 1)
                : _maxStripe;
            Debug.Print(DebugUtility.CreateReportString("FabricPayloadMux", "NextOperationLength",
                "Generated stripe length",
                opLen));
            return opLen;
        }
    }
#endif
}