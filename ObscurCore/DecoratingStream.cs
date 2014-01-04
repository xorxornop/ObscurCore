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
    /// </summary>
	public abstract class DecoratingStream : Stream
	{
		/// <summary>
		/// Default amount of data a buffer associated with this stream must store to avoid I/O errors.
		/// </summary>
		private const int DefaultBufferRequirement = 1024; // 1 KB

		protected bool Disposed;
		protected bool Finished;
		protected Stream Binding;

		private readonly bool _closeOnDispose;

		/// <summary>
		/// Set this field in the constructor of a derived class to indicate how much data the base stream 
		/// must have access to mid-operation to avoid I/O errors. Depends on behaviour of derived class logic.
		/// </summary>
		private int? _bufferRequirement = null;

		/// <summary>
		/// Stream that decorator writes to or reads from.
		/// </summary>
		/// <value>Stream binding.</value>
		public Stream DecoratorBinding { get { return Binding; } }

		/// <summary>
		/// Whether the stream that decorator writes/reads to/from is also a <see cref="ObscurCore.DecoratingStream"/>.
		/// </summary>
		/// <value><c>true</c> if binding is decorator; otherwise, <c>false</c>.</value>
		public bool BindingIsDecorator
		{
			get { return DecoratorBinding is DecoratingStream; }
		}

		/// <summary>
		/// What I/O mode of the decorator is active.
		/// </summary>
		/// <value><c>true</c> if writing, <c>false</c> if reading.</value>
		public bool Writing { get; private set; }

		public long BytesIn { get; protected set; }
		public long BytesOut { get; protected set; }

		/// <summary>
		/// How many bytes must be kept in reserve to avoid I/O errors. 
		/// When writing, this amount reflects capacity that must be free/empty to accomodate a write. 
		/// When reading, it reflects data that must be available to accomodate a read.
		/// </summary>
		/// <remarks>
		/// Clearly, this cannot apply for the ends of streams; 
		/// this being violated is the means of end-of-stream detection.
		/// </remarks>
		public int BufferSizeRequirement
		{
			get { return GetBufferRequirement(0) ?? DefaultBufferRequirement; }
			protected set { _bufferRequirement = value; }
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.DecoratingStream"/> class. 
		/// </summary>
		/// <param name="binding">Stream to bind decoration functionality to.</param>
		/// <param name="writing">If set to <c>true</c>, stream is used for writing-only, as opposed to reading-only.</param>
		/// <param name="closeOnDispose">If set to <c>true</c>, when stream is closed, bound stream will also be closed.</param>
		protected DecoratingStream (Stream binding, bool writing, bool closeOnDispose) 
		{
			Binding = binding;
			Writing = writing;
			_closeOnDispose = closeOnDispose;
		}

		/// <summary>
		/// Determine the maximum of the minimum size buffers required for 
		/// reliable I/O in a sequence of bound streams.
		/// </summary>
		/// <returns>The buffer requirement.</returns>
		/// <param name="maxFound">Maximum of the minimum sizes found thus far in recursive call.</param>
		protected int? GetBufferRequirement(int maxFound) {
			var dc = DecoratorBinding as DecoratingStream;
			if (dc != null) {
				var bindingRequirement = dc.GetBufferRequirement (maxFound);
				if (bindingRequirement.HasValue) {
					return Math.Max (maxFound, bindingRequirement.Value);
				}
			}
			return _bufferRequirement;
		}

		/// <summary>
		/// Check if disposed or finished (throw exception if either).
		/// </summary>
		protected void CheckIfCanDecorate() {
			if (Disposed) 
				throw new ObjectDisposedException(GetType().Name);
			if (Finished)
				throw new InvalidOperationException ();
		}

		public override void WriteByte (byte b) {
			CheckIfCanDecorate ();
			DecoratorBinding.WriteByte(b);
			BytesIn++;
			BytesOut++;
		}

		public override void Write (byte[] buffer, int offset, int count) {
			CheckIfCanDecorate ();
			DecoratorBinding.Write(buffer, offset, count);
			BytesIn += count;
			BytesOut += count;
		}

		/// <summary>
		/// Write exact quantity of bytes (after decoration) to the destination.
		/// </summary>
		/// <returns>The quantity of bytes taken from the source stream to fulfil the request.</returns>
		/// <param name="source">Source.</param>
		/// <param name="length">Length.</param>
		public abstract long WriteExactlyFrom(Stream source, long length);

		public override int ReadByte () {
			if (Disposed) 
				throw new ObjectDisposedException(GetType().Name);
			if (Finished)
				return -1;
			BytesIn++;
			BytesOut++;
			return DecoratorBinding.ReadByte();
		}

		public override int Read (byte[] buffer, int offset, int count) {
			CheckIfCanDecorate ();
			int readBytes = DecoratorBinding.Read(buffer, offset, count);
			BytesIn += readBytes;
			BytesOut += readBytes;
			return readBytes;
		}

		/// <summary>
		/// Read an exact amount of bytes from the stream binding and write them 
		/// (after decoration) to the destination.
		/// </summary>
		/// <returns>The quantity of bytes written to the destination stream.</returns>
		/// <param name="destination">Stream to write output to.</param>
		/// <param name="length">Quantity of bytes to read.</param>
		public abstract long ReadExactlyTo(Stream destination, long length, bool finishing = false);

		public override bool CanRead {
			get { return DecoratorBinding.CanRead; }
		}

		public override bool CanWrite {
			get { return DecoratorBinding.CanWrite; }
		}

		public override bool CanSeek {
			get { return Binding.CanSeek; }
		}

		public override long Length {
			get { return Binding.Length; }
		}

		public override long Position {
			get { return DecoratorBinding.Position; }
			set {
				if(!CanSeek) {
					throw new NotSupportedException ();
				}
				//Binding.Position = value;
				Binding.Seek (value, SeekOrigin.Begin);
			}
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
        /// Changes the stream that is written to or read from from this decorating stream.
        /// Writing/Reading mode is not reassignable without object reconstruction.
        /// </summary>
        /// <param name="newBinding">The stream that the decorator will be bound to after method completion.</param>
        /// <param name="reset">Whether to reset the rest of the decorator state in addition to the stream binding.</param>
		/// <param name="finish">Whether to finalise the existing decoration operation before resetting. Only applicable if resetting.</param>
        public void ReassignBinding(Stream newBinding, bool reset = true, bool finish = false) {
            if(newBinding == null || newBinding == Stream.Null) throw new ArgumentNullException("newBinding", "Stream is null, cannot reassign.");
            if (reset) Reset (finish);
			Binding = newBinding;
			Finished = false;
        }

		protected virtual void Reset(bool finish = false) {
			if (finish) Finish ();
			BytesIn = 0;
			BytesOut = 0;
			Finished = false;
		}

		/// <summary>
		/// Finish the decoration operation (whatever that may constitute in a derived implementation). 
		/// Could be done before a close or reset.
		/// </summary>
		protected virtual void Finish() {
			if (Finished)
				return;
			Finished = true;
		}

		public override void Close () {
			this.Dispose (true);
			GC.SuppressFinalize (this);
		}

		protected override void Dispose (bool disposing) {
			try {
				if (!Disposed) {
					if (disposing) {
						// dispose managed resources
						Finish ();
						if(this.Binding != null && _closeOnDispose) {
							this.Binding.Close ();
						}
						this.Binding = null;
					}
				}
				Disposed = true;
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
