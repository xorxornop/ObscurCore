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
	public sealed class RingByteBuffer
	{
		public int Capacity { get; private set; }
		public int Length { get; private set; }

		public int Spare { get { return Capacity - Length; } }

		private readonly byte[] _buffer;
		private int _head, _tail;

		public RingByteBuffer (int capacity) {
			Capacity = capacity;
			_buffer = new byte[Capacity];
		}

		public RingByteBuffer (int capacity, byte[] buffer) : this(capacity) {
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

        /// <summary>
        /// Reads a stream directly into the ringbuffer. 
        /// Avoids the overhead of creating a byte array.
        /// </summary>
        /// <param name="source">Stream to take bytes from to write to the ringbuffer.</param>
        /// <param name="count">Number of bytes to take/read.</param>
        public void PutFrom(Stream source, int count) {
            if (count + Length > Capacity) {
				throw new InvalidOperationException("Buffer capacity insufficient for write operation. " + 
				                                    "Write a smaller quantity relative to the capacity to avoid this.");
			}

            if (_tail + count >= Capacity) {
				var chunkSize = Capacity - _tail;
                source.Read(_buffer, _tail, chunkSize);
				_tail = 0;
				count -= chunkSize;
				Length += chunkSize;
			}
            source.Read(_buffer, _tail, count);
            _tail += count;
			Length += count;
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

        public void TakeTo(Stream destination, int count) {
            if (count > Length)
				throw new ArgumentException("Buffer contents insufficient for read operation. " +
				                                    "Request a smaller quantity relative to the capacity to avoid this.", "count");
            if(count == 0) return;

			if (_head + count >= Capacity) {
				var chunkSize = Capacity - _head;
                destination.Write(_buffer, _head, chunkSize);
				_head = 0;
				count -= chunkSize;
				Length -= chunkSize;
			}
			destination.Write(_buffer, _head, count);
			_head += count;
			Length -= count;
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

		/// <summary>
		/// Set every byte in the internal array (buffer) to zero. 
		/// Can be used as a security feature, or convenience method for resetting state.
		/// </summary>
		public void Erase() {
			Array.Clear (_buffer, 0, _buffer.Length);
			_head = 0;
			_tail = 0;
			Length = 0;
		}

		public void Reset() {
			Erase ();
		}

		public byte[] ToArray () {
			return Take(Length);
		}
	}
}
