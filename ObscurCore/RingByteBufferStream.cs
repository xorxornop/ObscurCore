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
using System.IO;

namespace ObscurCore
{
    public sealed class RingByteBufferStream : Stream
    {
        private readonly RingByteBuffer _ringBuffer;

        public RingByteBufferStream(int capacity) {
            _ringBuffer = new RingByteBuffer(capacity);
        }

        public override bool CanRead {
            get { return _ringBuffer.Length > 0; }
        }

        public override bool CanSeek {
            get { return _ringBuffer.Length > 0; }
        }

        public override bool CanWrite {
            get { return _ringBuffer.Length < _ringBuffer.Capacity; }
        }

        /// <summary>
        /// Discards all current data in the buffer!
        /// </summary>
        public override void Flush () {
            // Do nothing
        }

        public override long Length {
            get { return _ringBuffer.Length; }
        }

        public override long Position {
            get { return 0; }
            set {
                throw new NotSupportedException();
            }
        }

        public override int Read (byte[] buffer, int offset, int count) {
            if(_ringBuffer.Length == 0) throw new EndOfStreamException();
            count = Math.Min(count, _ringBuffer.Length);
            _ringBuffer.Take(buffer, offset, count);
            return count;
        }

        public int Read (byte[] buffer, int offset, int count, bool exact) {
            if(_ringBuffer.Length == 0) throw new EndOfStreamException();
            if (exact && _ringBuffer.Length < count) count = _ringBuffer.Length;
            _ringBuffer.Take(buffer, offset, count);
            return count;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="destination">Destination to write bytes that are read.</param>
        /// <param name="count">Number of bytes to read/write.</param>
        /// <param name="exact">To read less bytes than specified is unacceptable.</param>
        /// <returns>Number of bytes written (read from the buffer).</returns>
        public int ReadTo (Stream destination, int count, bool exact) {
            if(_ringBuffer.Length == 0) throw new EndOfStreamException();
            if(exact && _ringBuffer.Length < count) count = _ringBuffer.Length;
            _ringBuffer.TakeTo(destination, count);
            return count;
        }

        /// <summary>
        /// Write to the ringbuffer using a stream source. 
        /// Non-standard stream method for high performance.
        /// </summary>
        /// <param name="source">Source to take bytes from for writing.</param>
        /// <param name="count">Number of bytes to read/write.</param>
        /// <returns>Number of bytes written (read from the source).</returns>
        public int WriteFrom(Stream source, int count) {
            _ringBuffer.PutFrom(source, count);
            return count;
        }

        /// <summary>
        /// Advances the stream a specified number of bytes. 
        /// Skipped data is non-recoverable; state is not remembered, as position cannot be reverted.
        /// </summary>
        /// <param name="offset">Number of bytes to skip ahead.</param>
        /// <param name="origin">Use only values of Begin or Current (same effect).</param>
        public override long Seek(long offset, SeekOrigin origin) {
            if(origin == SeekOrigin.End) throw new ArgumentException("Seek only applicable from current stream position (Begin/Current).");
            return _ringBuffer.Skip((int)offset);
        }

        public override void SetLength (long value) {
            throw new NotSupportedException("Capacity must be set on construction.");
        }

        public override void Write (byte[] buffer, int offset, int count) {
            _ringBuffer.Put(buffer, offset, count);
        }

        protected override void Dispose(bool disposing)
        {
            _ringBuffer.Skip(_ringBuffer.Length);
            base.Dispose(disposing);
        }
    }
}