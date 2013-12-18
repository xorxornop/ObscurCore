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
        /// <summary>
        /// Initializes a new instance of a stream multiplexer.
        /// </summary>
        /// <param name="writing">If set to <c>true</c>, writing a multiplexed stream.</param>
        /// <param name="multiplexedStream">Stream being written to (destination; multiplexing) or read from (source; demultiplexing).</param>
        /// <param name="streams">Streams being read from (sources; multiplexing), or written to (destinations; demultiplexing).</param>
        /// <param name="transformFuncs">Transform funcs.</param>
        /// <param name="maxOpSize">Maximum size that any single operation will be. Used to size copy buffer.</param>
        protected PayloadMux(bool writing, Stream multiplexedStream, IList<IStreamBinding> streams,
            IList<Func<Stream, DecoratingStream>> transformFuncs, int maxOpSize = 16384)
        {
            if (streams.Count == 0 || transformFuncs.Count == 0)
                throw new ArgumentException("No streams and/or transforms supplied for multiplexing operations.");
            else if (streams.Count != transformFuncs.Count)
                throw new ArgumentException(
                    "Streams and transforms supplied for multiplexing operations are mismatched in quantity.");

            this.Writing = writing;
            _multiplexed = multiplexedStream;
            _items.AddRange(streams);
            _accumulatorExternal = new long[streams.Count];
            _accumulatorInternal = new long[streams.Count];
            _copyBuffer = new byte[maxOpSize];

            // Set up lazy-initialised transforms using Func value factories
            for (var i = 0; i < transformFuncs.Count; i++) {
                /* Make the buffer big enough to satisfy the transform stack's requirements, 
                 * but not bigger than the item, or transform+copybuffer requirements. */
                var relevantItemLength = Writing ? _items[i].ExternalLength : _items[i].InternalLength;
                var decoratingStream = transformFuncs[i](Stream.Null); // TODO: Fix this nasty hack

                var ringBufferSize = (int) Math.Min(relevantItemLength, decoratingStream.BufferSizeRequirement + maxOpSize);

                //var buffer = new RingByteBufferStream((int) Math.Min(relevantItemLength, Math.Max(Math.Min
                //    (decoratingStream.BufferSizeRequirement, relevantItemLength),
                //    decoratingStream.BufferSizeRequirement + maxOpSize)));

                var buffer = new RingByteBufferStream(ringBufferSize);

                _buffers.Add(buffer);
                decoratingStream.SetStreamBinding(buffer, false); // TODO: Fix this nasty hack

                this._transforms.Add(transformFuncs[i](buffer));
            }
        }

        #region Fields

        //protected CancellationToken token; // implement cancellation later!

        /// <summary>
        /// The persistent copy buffer.
        /// </summary>
        private readonly byte[] _copyBuffer;

        private readonly Stream _multiplexed;
        private readonly List<IStreamBinding> _items = new List<IStreamBinding>();
        private readonly List<RingByteBufferStream> _buffers = new List<RingByteBufferStream>();
        private readonly List<DecoratingStream> _transforms = new List<DecoratingStream>();
        private readonly long[] _accumulatorExternal, _accumulatorInternal;

        #endregion

        #region Properties

        public bool Writing { get; private set; }

        protected int CurrentIndex { get; set; }

        public Guid CurrentItemIdentifier {
            get { return CurrentItem.Identifier; }
        }

        public int ItemCount {
            get { return _items.Count; }
        }

        public int ItemsCompleted { get; protected set; }

        public int Overhead { get; protected set; }

        public long TotalSourceIO {
            get { return GetTotalIO(true); }
        }

        public long TotalDestinationIO {
            get { return GetTotalIO(false); }
        }

        /// <summary>
        /// Gets the source.
        /// </summary>
        /// <value>The source.</value>
        protected Stream CurrentSource {
            get { return Writing ? _items[CurrentIndex].StreamBinding : _multiplexed; }
        }

        /// <summary>
        /// Gets the buffer.
        /// </summary>
        /// <value>The buffer.</value>
        protected RingByteBufferStream CurrentItemBuffer {
            get { return _buffers[CurrentIndex]; }
        }

        protected Stream CurrentDestination {
            get { return Writing ? _multiplexed : _items[CurrentIndex].StreamBinding; }
        }

        protected DecoratingStream CurrentItemTransform {
            get { return _transforms[CurrentIndex]; }
        }

        protected IStreamBinding CurrentItem {
            get { return _items[CurrentIndex]; }
        }

        /// <summary>
        /// How many bytes have been read from the source.
        /// </summary>
        /// <remarks>
        /// When writing, this is the external size. When reading, it is the internal size.
        /// Used as a reliable reference of how far through processing the item is.
        /// When items are complete, they are expressed as the negative counterpart.
        /// </remarks>
        protected long SourceAccumulator {
            get { return Writing ? _accumulatorExternal[CurrentIndex] : _accumulatorInternal[CurrentIndex]; }
            set {
                if (Writing) {
                    _accumulatorExternal[CurrentIndex] = value;
                } else {
                    _accumulatorInternal[CurrentIndex] = value;
                }
            }
        }

        /// <summary>
        /// How many bytes have been written to the destination. 
        /// Delayed if reading - do not use for critical logic.
        /// </summary>
        /// <remarks>
        /// When writing, this is the external size. When reading, it is the internal size.
        /// Used as an indication of how far through processing the item is.
        /// When items are complete, they are expressed as the negative counterpart.
        /// </remarks>
        protected long DestinationAccumulator {
            get { return Writing ? _accumulatorExternal[CurrentIndex] : _accumulatorInternal[CurrentIndex]; }
            set {
                if (Writing) {
                    _accumulatorInternal[CurrentIndex] = value;
                } else {
                    _accumulatorExternal[CurrentIndex] = value;
                }
            }
        }

        /// <summary>
        /// How many bytes the buffer must contain before operations are performed with it.
        /// </summary>
        protected virtual int CurrentItemBufferThreshold {
            get { return CurrentItemTransform.BufferSizeRequirement; }
        }

        #endregion

        #region Core methods

        /// <summary>
        /// Executes a single multiplexing operation.
        /// </summary>
        public void ExecuteSingle() {
            if (SourceAccumulator == 0) {
                if (Writing) {
                    Overhead += EmitHeader();
                } else {
                    Overhead += ConsumeHeader();
                }
            }

            var nextOpLen = NextOperationLength();
            var targetPosition = Math.Min(SourceAccumulator + nextOpLen, Writing ? CurrentItem.ExternalLength : CurrentItem.InternalLength);

            Debug.Print(DebugUtility.CreateReportString("PayloadMux", "ExecuteSingle", "Target position (item-relative)",
                    targetPosition));

            bool sourceDepleted = false;
            while (SourceAccumulator < targetPosition) {
                //var opLength =
                    //(int) (Math.Min(SourceAccumulator + _copyBuffer.Length, targetPosition) - SourceAccumulator);

                var opLength = (int) Math.Min(_copyBuffer.Length, targetPosition - SourceAccumulator);


                var bytesRead = CurrentSource.Read(_copyBuffer, 0, opLength);
                if (Writing) {
                    CurrentItemTransform.Write(_copyBuffer, 0, bytesRead);
                } else {
                    CurrentItemBuffer.Write(_copyBuffer, 0, bytesRead);
                }

                SourceAccumulator += bytesRead;

                if (SourceAccumulator == (Writing ? CurrentItem.ExternalLength : CurrentItem.InternalLength)) {
                    sourceDepleted = true;
                    if(Writing) CurrentItemTransform.Close();
                }

                // Write the data in buffers out to destination if there's enough there or the item is finished.
                while (CurrentItemBuffer.Length >= CurrentItemBufferThreshold || (sourceDepleted && CurrentItemBuffer.Length > 0)) {
                    //var readAmount = (int) Math.Min(CurrentItemBuffer.Length, _copyBuffer.Length);
                    var bufferBytesRead = Writing
                        ? CurrentItemBuffer.Read(_copyBuffer, 0, CurrentItemBufferThreshold)
                        : CurrentItemTransform.Read(_copyBuffer, 0, CurrentItemBufferThreshold);
                    var startPos = CurrentDestination.Position;
                    CurrentDestination.Write(_copyBuffer, 0, bufferBytesRead);
                    DestinationAccumulator += CurrentDestination.Position - startPos;
                }
            }

            // If we're done we need to do some things.
            if (sourceDepleted) {
                if (Writing) {
                    Overhead += EmitTrailer();
                } else {
                    Overhead += ConsumeTrailer();
                }

                Array.Clear(_copyBuffer, 0, _copyBuffer.Length); // obsessive-compulsive, and also for debugging
                // Mark the item as completed in the accumulators
                SourceAccumulator *= -1;
                DestinationAccumulator *= 1;
                ItemsCompleted++;
                if(Writing) CurrentSource.Close();

                Debug.Print(DebugUtility.CreateReportString("PayloadMux", "ExecuteSingle", "[*** END OF ITEM ***]",
                    CurrentIndex));
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
            if (ItemsCompleted == _items.Count) {
                return false;
            } else {
                // when accumulator # is under 0 (-ve), means item was finished.
                do {
                    NextSource();
                } while (SourceAccumulator < 0);

                Debug.Print(DebugUtility.CreateReportString("PayloadMux", "AdvanceSource", "Selected stream index",
                    CurrentIndex));

                return true;
            }
        }

        #endregion

        #region Extensible
        /// <summary>
        /// Determine the index of the next stream to use in an I/O operation (whether to completion or just a buffer-full).
        /// </summary>
        /// <remarks>May be overriden in a derived class to provide for advanced stream selection logic.</remarks>
        /// <returns>The next stream index.</returns>
        protected virtual int NextSource() {
            CurrentIndex++;
            if (CurrentIndex == _items.Count) CurrentIndex = 0;
            return CurrentIndex;
        }

        /// <summary>
        /// Returns the length of the next I/O operation to take place. 
        /// Depending on implementation in derived classes, may advance state also.
        /// </summary>
        /// <remarks>May be overriden in a derived class to provide for advanced operation length selection logic.</remarks>
        /// <returns>The next operation length.</returns>
        protected virtual long NextOperationLength() {
            return CurrentItem.ExternalLength;
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

        #region Utility methods

        protected long GetSourceAccumulator(int index) {
            return Writing ? _accumulatorExternal[index] : _accumulatorInternal[index];
        }

        protected long GetDestinationAccumulator(int index) {
            return Writing ? _accumulatorInternal[index] : _accumulatorExternal[index];
        }


        public long GetItemIO(int index) {
            return GetItemIO(index, true);
        }

        public long GetItemIO(int index, bool source) {
            if (index > _items.Count - 1)
                throw new ArgumentException("Out of bounds.", "index");
            return Math.Abs(source ? GetSourceAccumulator(index) : GetDestinationAccumulator(index));
        }

        public long? GetItemIO(Guid identifier, out bool completed) {
            return GetItemIO(identifier, out completed, true);
        }

        public long? GetItemIO(Guid identifier, out bool completed, bool source) {
            int index = _items.FindIndex(item => item.Identifier.Equals(identifier));
            if (index == -1) {
                completed = false;
                return null;
            }
            var result = GetItemIO(index, source);
            completed = result < 0;
            return result;
        }

        private long GetTotalIO(bool source) {
            var collection = (Writing == source) ? _accumulatorExternal : _accumulatorInternal;
            var sum = collection.Sum(num => Math.Abs(num));
            return sum + Overhead;
        }

        #endregion
    }
}