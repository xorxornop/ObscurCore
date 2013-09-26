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
	public abstract class DecoratingStream : Stream
	{
		protected Stream BoundStream;

		private bool _disposed;
		protected readonly bool CloseOnDispose;

        protected const string      NotEffluxError =    "Stream is configured for write-direction/efflux processing, and so may only be written to.",
		                            NotInfluxError =    "Stream is configured for read-direction/influx processing, and so may only be read from.";

		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.DecoratingStream"/> class without a stream binding at construction time. 
		/// </summary>
		/// <param name="writing">If set to <c>true</c>, stream is used for writing-only, as opposed to reading-only.</param>
		/// <param name="closeOnDispose">If set to <c>true</c>, when stream is closed, bound stream will also be closed.</param>
		protected DecoratingStream (bool writing, bool closeOnDispose) {
			Writing = writing;
			CloseOnDispose = closeOnDispose;
		}

		protected DecoratingStream (Stream binding, bool writing, bool closeOnDispose) : this(writing, closeOnDispose) {
			BoundStream = binding;
		}

		public bool Writing { get; protected set; }
		public long BytesIn { get; protected set; }
		public long BytesOut { get; protected set; }

		/// <summary>
		/// Set this field in the constructor of a derived class to indicate how much data the base stream 
		/// must have access to mid-operation to avoid I/O errors. Depends on behaviour of derived class logic.
		/// </summary>
		protected int? BufferRequirementOverride = null;

		/// <summary>
		/// Default amount of data a buffer associated with this stream must store to avoid I/O errors.
		/// </summary>
		private const int DefaultBufferReq = 8192; // 8 KB

		/// <summary>
		/// How much data a buffer supplying or recieving data from this stream instance must store to avoid I/O errors.
		/// </summary>
		public int BufferSizeRequirement
		{
			get { return GetMaxBufferReq(0); }
			protected set { BufferRequirementOverride = value; }
		}

		private int GetMaxBufferReq(int maxFound) {
			var dc = BoundStream as DecoratingStream;
			var highest = Math.Max(maxFound, BufferRequirementOverride ?? DefaultBufferReq);
			return dc != null ? Math.Max(dc.GetMaxBufferReq(highest), highest) : highest;
		}

		public override void Write (byte[] buffer, int offset, int count) {
			if (!Writing) throw new InvalidOperationException(NotEffluxError);
			BoundStream.Write(buffer, offset, count);
			BytesIn += count;
			BytesOut += count;
		}

		public override void WriteByte (byte b) {
			if (!Writing) throw new InvalidOperationException(NotEffluxError);
			BoundStream.WriteByte(b);
			BytesIn++;
			BytesOut++;
		}

		public override int ReadByte () {
			if (Writing) throw new InvalidOperationException(NotEffluxError);
			BytesIn++;
			BytesOut++;
			return BoundStream.ReadByte();
		}

		public override int Read (byte[] buffer, int offset, int count) {
			if (Writing) throw new InvalidOperationException(NotInfluxError);
			var readBytes = BoundStream.Read(buffer, offset, count);
			BytesIn += count;
			BytesOut += count;
			return readBytes;
		}

		public override bool CanRead {
			get {
				if (_disposed) throw new ObjectDisposedException("DecoratingStream");
				return !Writing && BoundStream.CanRead;
			}
		}

		public override bool CanWrite {
			get {
				if (_disposed) throw new ObjectDisposedException("DecoratingStream");
				return Writing && BoundStream.CanWrite;
			}
		}

		public override bool CanSeek {
			get {
				if (_disposed) throw new ObjectDisposedException("DecoratingStream");
				else return false;
			}
		}

		public sealed override long Length {
			get { throw new NotSupportedException(); }
		}

		public sealed override long Position {
			get { throw new NotSupportedException(); }
			set { throw new NotSupportedException(); }
		}

		public sealed override long Seek (long offset, SeekOrigin origin) {
			throw new NotSupportedException();
		}

		public sealed override void SetLength (long length) {
			BoundStream.SetLength(length);
		}

		public override void Flush () {
			if (_disposed) throw new ObjectDisposedException("DecoratingStream");
			BoundStream.Flush();
		}

		/*public void Dispose () {
            Dispose(true);
            GC.SuppressFinalize(this);
        }*/

		protected override void Dispose (bool disposing) {
			try {
				if (_disposed) return;
				if (disposing) {
					if (BoundStream != null && CloseOnDispose) BoundStream.Close();
				}
				//_stream = null; // Unsure if actually necessary if using the _disposed field? Disabled for now.
				_disposed = true;
			}
			finally {
				base.Dispose(disposing);
			}
		}

        /// <summary>
        /// Changes the stream that is written to or read from from this decorating stream.
        /// Writing/Reading mode is not reassignable without object reconstruction.
        /// </summary>
        /// <param name="newBinding"></param>
        /// <param name="reset"></param>
        public void ReassignStreamBinding(Stream newBinding, bool reset) {
            if(newBinding == null || newBinding == Stream.Null) throw new ArgumentNullException("newBinding", "Stream is null, cannot reassign.");
            if (reset) {
                BytesIn = 0;
                BytesOut = 0;
            }
        }
	}
}
