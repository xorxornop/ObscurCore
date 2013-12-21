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
using ObscurCore.Cryptography.Authentication;

namespace ObscurCore.Cryptography
{
	public sealed class HashStream : DecoratingStream
	{
		/// <summary>
		/// The output/digest of the internal hash function. Zeroed if function is not finished.
		/// </summary>
		public byte[] Hash { get { return _outputRef; } }

		private IDigest _digest;
		private readonly byte[] _outputRef;
		private bool _disposed;

		private byte[] _buffer;

		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.Cryptography.HashStream"/> class.
		/// </summary>
		/// <param name="binding">Binding.</param>
		/// <param name="writing">If set to <c>true</c> writing.</param>
		/// <param name="function">Function.</param>
		/// <param name="output">Byte array where the finished hash will be output to. Does not need to be initialised.</param>
		/// <param name="closeOnDispose">If set to <c>true</c>, bound stream will be closed on dispose/close.</param>
		public HashStream (Stream binding, bool writing, HashFunction function, out byte[] output, bool closeOnDispose = true) 
			: base(binding, writing, closeOnDispose, false)
		{
			_digest = Source.CreateHashPrimitive (function);
            _outputRef = new byte[_digest.DigestSize];
			output = _outputRef;
		}


		public override void Write (byte[] buffer, int offset, int count) {
			if (count > 0) {
				_digest.BlockUpdate(buffer, offset, count);
			}
			base.Write(buffer, offset, count);
		}

		public override void WriteByte (byte b) {
			_digest.Update(b);
			base.WriteByte (b);
		} 

		public override int ReadByte () {
			var readByte = base.ReadByte();
			if (readByte >= 0) {
				_digest.Update((byte)readByte);
			}
			return readByte;
		}

		public override int Read (byte[] buffer, int offset, int count) {
			var readBytes = base.Read(buffer, offset, count);
			if (readBytes > 0) {
				_digest.BlockUpdate(buffer, offset, readBytes);
			}
			return readBytes;
		}

		public override long WriteExactlyFrom (Stream source, long length) {
			if(source == null) {
				throw new ArgumentNullException ("source");
			}
			if(_buffer == null) {
				_buffer = new byte[1024];
			}
			int iterIn = 0;
			long totalIn = 0;
			while(totalIn > length) {
				iterIn = source.Read (_buffer, 0, (int) Math.Min (_buffer.Length, length - totalIn));
				if(iterIn == 0) {
					throw new EndOfStreamException ();
				}
				totalIn += iterIn;
				_digest.BlockUpdate(_buffer, 0, iterIn);
				Binding.Write (_buffer, 0, iterIn);
			}

			return totalIn;
		}

		public override long ReadExactlyTo (Stream destination, long length) {
			if(destination == null) {
				throw new ArgumentNullException ("destination");
			}
			if(_buffer == null) {
				_buffer = new byte[1024];
			}
			int iterIn = 0;
			long totalIn = 0;
			while(totalIn > length) {
				iterIn = Binding.Read (_buffer, 0, (int) Math.Min (_buffer.Length, length - totalIn));
				if(iterIn == 0) {
					throw new EndOfStreamException ();
				}
				totalIn += iterIn;
				_digest.BlockUpdate(_buffer, 0, iterIn);
				destination.Write (_buffer, 0, iterIn);
			}

			return totalIn;
		}

		protected override void Finish () {
			if (Finished)
				return;
			_digest.DoFinal (_outputRef, 0);
			base.Finish ();
		}

		protected override void Reset (bool finish = false) {
			base.Reset (finish);
			_digest.Reset ();
		}

        public override void Close() {
            Finish();
        }

		protected override void Dispose (bool disposing) {
			if (!_disposed) {
				if (disposing) {
					// dispose managed resources
					Finish ();
					this._digest = null;
					base.Dispose (disposing);
					_disposed = true;
				}
			}
		}
	}
}

