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
	/// <summary>
	/// Simple cyclic/ring data buffer.
	/// </summary>
	/// <remarks>
	/// Makes efficient use of memory.
	/// Ensure initialised capacity can hold typical use case requirement with some overflow tolerance.	
	/// </remarks>		
	public sealed class CyclicByteBuffer
	{
		public int Capacity { get; private set; }
		public int Length { get; private set; }

		public int Spare { get { return Capacity - Length; } }

		private readonly byte[] _buffer;
		private int _head, _tail;

		public CyclicByteBuffer (int capacity) {
			Capacity = capacity;
			_buffer = new byte[Capacity];
		}

		public CyclicByteBuffer (int capacity, byte[] buffer) : this(capacity) {
			Capacity = capacity;
			_buffer = new byte[Capacity];
			Buffer.BlockCopy(buffer, 0, _buffer, 0, buffer.Length);
			_tail += buffer.Length;
			Length += _tail;
		}

		public void Put (byte[] buffer) {
			Put(buffer, 0, buffer.Length);
		}

		public void Put (byte[] buffer, int offset, int count)
		{
			if (count + Length > Capacity) {
				throw new InvalidOperationException("Buffer capacity insufficient for write operation. " + 
				                                    "Write a smaller quantity relative to the capacity to avoid this.");
			}

			if (_tail + count >= Capacity) {
				var chunkSize = Capacity - _tail;
				Buffer.BlockCopy(buffer, offset, _buffer, _tail, chunkSize);
				_tail = 0;
				offset += chunkSize;
				count -= chunkSize;
				Length += chunkSize;
			}
			Buffer.BlockCopy(buffer, offset, _buffer, _tail, count);
			_tail += count;
			Length += count;
		}

		public void Put (byte input) {
			if (Length + 1 > Capacity) throw new InvalidOperationException("Buffer capacity insufficient for write operation.");
			_buffer[_tail++] = input;
			if (_tail == Capacity) _tail = 0;
			Length++;
		}

		public void Take (byte[] buffer) {
			Take(buffer, 0, buffer.Length);
		}

		public byte[] Take (int count) {
			var output = new byte[count];
			Take(output);
			return output;
		}

		public void Take (byte[] buffer, int offset, int count) {
			if (count > Length)
				throw new ArgumentException("Buffer contents insufficient for read operation. " +
				                                    "Request a smaller quantity relative to the capacity to avoid this.", "count");
			if (buffer.Length < offset + count)
				throw new ArgumentException("Destination array too small for requested output.", "buffer");

			if(count == 0) return;

			if (_head + count >= Capacity) {
				var chunkSize = Capacity - _head;
				Buffer.BlockCopy(_buffer, _head, buffer, offset, chunkSize);
				_head = 0;
				offset += chunkSize;
				count -= chunkSize;
				Length -= chunkSize;
			}
			Buffer.BlockCopy(_buffer, _head, buffer, offset, count);
			_head += count;
			Length -= count;
		}

		public byte Take () {
			if (Length == 0) throw new InvalidOperationException("Buffer contents insufficient for read operation.");

			Length--;
			var output = _buffer[_head++];
			if (_head == Capacity) _head = 0;

			return output;
		}

		/// <summary>
		/// Advances the stream a specified number of bytes. 
		/// Skipped data is non-recoverable; state is not remembered, as position cannot be reverted.
		/// </summary>
		/// <param name="offset">Number of bytes to skip ahead.</param>
		/// <param name="throwOnInsufficient">Throw an exception if the offset specified exceeds the available data.</param>
		public int Skip(int offset, bool throwOnInsufficient = true)
		{
			if (offset < 0) throw new ArgumentOutOfRangeException("offset", "Negative offset specified. Offsets must be positive.");
			if (offset > Length) {
				if (throwOnInsufficient) throw new ArgumentException("Offset specified exceeds data available.");
				offset = Length;
			}
			var skipped = offset;

			if (_head + offset > Capacity) {
				var remove = Capacity - _head;
				_head = 0;
				offset -= remove;
				Length -= remove;
			}
			_head += offset;
			Length -= offset;

			return skipped;
		}

		public byte[] ToArray () {
			return Take(Length);
		}
	}

	public sealed class CyclicMemoryStream : Stream
	{
		private readonly CyclicByteBuffer _ringBuffer;

		public CyclicMemoryStream(int capacity) {
			_ringBuffer = new CyclicByteBuffer(capacity);
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
		    count = Math.Min(count, _ringBuffer.Length);
			_ringBuffer.Take(buffer, offset, count);
			return count;
		}

		public int Read (byte[] buffer, int offset, int count, bool exact) {
			if (exact && _ringBuffer.Length < count) count = _ringBuffer.Length;
			_ringBuffer.Take(buffer, offset, count);
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
