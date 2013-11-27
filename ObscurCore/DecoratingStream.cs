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
    /// Base class for ObscurCore's decorating streams to inherit from. 
    /// Provides baseline functionality, such as I/O directionality enforcement, and buffer information passthrough. 
    /// </summary>
	public abstract class DecoratingStream : Stream
	{
		public bool Writing { get; protected set; }
		public long BytesIn { get; protected set; }
		public long BytesOut { get; protected set; }

		protected Stream Binding { get; private set; }

		/// <summary>
		/// How much data a buffer supplying or recieving data from this stream instance must store to avoid I/O errors.
		/// </summary>
		public int BufferSizeRequirement
		{
			get { return GetMaxBufferReq(0); }
			protected set { BufferRequirementOverride = value; }
		}


		private bool _disposed;

		private readonly bool _directionalityEnforced;
        private bool _finished;
		private readonly bool _closeOnDispose;

		/// <summary>
		/// Set this field in the constructor of a derived class to indicate how much data the base stream 
		/// must have access to mid-operation to avoid I/O errors. Depends on behaviour of derived class logic.
		/// </summary>
		protected int? BufferRequirementOverride = null;

		/// <summary>
		/// Default amount of data a buffer associated with this stream must store to avoid I/O errors.
		/// </summary>
		private const int DefaultBufferReq = 8192; // 8 KB

        protected string 	NotEffluxError =    "Stream is configured for write-direction/efflux processing, and so may only be written to.",
		                 	NotInfluxError =    "Stream is configured for read-direction/influx processing, and so may only be read from.";


		protected DecoratingStream (bool writing, bool closeOnDispose, bool enforce = true) {
			Writing = writing;
			_closeOnDispose = closeOnDispose;
			_directionalityEnforced = enforce;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.DecoratingStream"/> class without a stream binding at construction time. 
		/// </summary>
		/// <param name="writing">If set to <c>true</c>, stream is used for writing-only, as opposed to reading-only.</param>
		/// <param name="closeOnDispose">If set to <c>true</c>, when stream is closed, bound stream will also be closed.</param>
		protected DecoratingStream (Stream binding, bool writing, bool closeOnDispose, bool enforce = true) 
			: this(writing, closeOnDispose, enforce)
		{
			Binding = binding;
		}


		private int GetMaxBufferReq(int maxFound) {
			var dc = Binding as DecoratingStream;
			var highest = Math.Max(maxFound, BufferRequirementOverride ?? DefaultBufferReq);
			return dc != null ? Math.Max(dc.GetMaxBufferReq(highest), highest) : highest;
		}

		public override void Write (byte[] buffer, int offset, int count) {
			CheckIfAllowed (true);
			Binding.Write(buffer, offset, count);
			BytesIn += count;
			BytesOut += count;
		}

		public override void WriteByte (byte b) {
			CheckIfAllowed (true);
			Binding.WriteByte(b);
			BytesIn++;
			BytesOut++;
		}

		public override int ReadByte () {
			CheckIfAllowed (false);
			if (Writing) throw new InvalidOperationException(NotEffluxError);
			BytesIn++;
			BytesOut++;
			return Binding.ReadByte();
		}

		public override int Read (byte[] buffer, int offset, int count) {
			CheckIfAllowed (false);
			if (Writing) throw new InvalidOperationException(NotInfluxError);
			var readBytes = Binding.Read(buffer, offset, count);
			BytesIn += count;
			BytesOut += count;
			return readBytes;
		}

		public override bool CanRead {
			get { return _directionalityEnforced ? !Writing && Binding.CanRead : Binding.CanRead; }
		}

		public override bool CanWrite {
			get { return _directionalityEnforced ? Writing && Binding.CanWrite : Binding.CanWrite; }
		}

		public override bool CanSeek {
			get { return Binding.CanSeek; }
		}

		public override long Length {
			get { return Binding.Length; }
		}

		public override long Position {
			get { return Binding.Position; }
			set {
				if(!CanSeek) {
					throw new NotSupportedException ();
				}
				Binding.Position = value;
			}
		}

        protected internal bool Finished {
            get { return _finished; }
        }

        public override long Seek (long offset, SeekOrigin origin) {
			return Binding.Seek (offset, origin);
		}

		public override void SetLength (long length) {
			Binding.SetLength(length);
		}

		public override void Flush () {
			Binding.Flush();
		}


		/// <summary>
		/// Finish the decoration operation, whatever that constitutes in a derived implementation. 
		/// Could be done before a close or reset.
		/// </summary>
		protected virtual void Finish() {
			if (_finished)
				return;
			// Nothing here
			_finished = true;
		}

        /// <summary>
        /// Changes the stream that is written to or read from from this decorating stream.
        /// Writing/Reading mode is not reassignable without object reconstruction.
        /// </summary>
        /// <param name="newBinding">The stream that the decorator will be bound to after method completion.</param>
        /// <param name="reset">Whether to reset the rest of the decorator state in addition to the stream binding.</param>
		/// <param name="finish">Whether to finalise the existing decoration operation before resetting. Only applicable if resetting.</param>
        public void SetStreamBinding(Stream newBinding, bool reset = true, bool finish = false) {
            if(newBinding == null || newBinding == Stream.Null) throw new ArgumentNullException("newBinding", "Stream is null, cannot reassign.");
            if (reset) Reset (finish);
        }

		protected virtual void Reset(bool finish = false) {
			if (finish) Finish ();
			BytesIn = 0;
			BytesOut = 0;
			_finished = false;
		}

		protected void CheckIfDisposed() {
			if (_disposed) throw new ObjectDisposedException(GetType().Name);
		}

		protected void CheckIfAllowed(bool writing) {
			if (!_directionalityEnforced) return;
			if (Writing && !writing) throw new InvalidOperationException(NotInfluxError);
			else if (!Writing && writing) throw new InvalidOperationException(NotEffluxError);
		}

		public override void Close () {
			this.Dispose (true);
			GC.SuppressFinalize (this);
		}

		protected override void Dispose (bool disposing) {
			try {
				if (!_disposed) {
					if (disposing) {
						// dispose managed resources
						Finish ();
						if(this.Binding != null && _closeOnDispose) {
							this.Binding.Close ();
						}
						this.Binding = null;
					}
				}
				_disposed = true;
			}
			finally {
				if(this.Binding != null) {
					this.Binding = null;
					base.Dispose(disposing);
				}
			}
		}
	}
}
