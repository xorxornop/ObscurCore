/*
CryptSharp
Copyright (c) 2010, 2013 James F. Bellinger <http://www.zer7.com/software/cryptsharp>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

using System;
using System.IO;
using BitManipulator;
using ObscurCore.Cryptography.Authentication;
using PerfCopy;

namespace ObscurCore.Cryptography.KeyDerivation.Primitives
{
	public class Pbkdf2 : Stream
	{
		#region PBKDF2
		byte[] _saltBuffer, _digest, _digestT1;
		IMac _hmacAlgorithm;
		int _iterations;

		/// <summary>
		/// Creates a new PBKDF2 stream.
		/// </summary>
		/// <param name="hmacAlgorithm">
		///     The HMAC primitive instance to use. Must be pre-initialised.
		/// </param>
		/// <param name="salt">
		///     The salt.
		///     A unique salt means a unique PBKDF2 stream, even if the original key is identical.
		/// </param>
		/// <param name="iterations">The number of iterations to apply.</param>
		public Pbkdf2(IMac hmacAlgorithm, byte[] salt, int iterations)
		{
			Helper.CheckNull("hmacAlgorithm", hmacAlgorithm);
			Helper.CheckNull("salt", salt);
			//Check.Length("salt", salt, 0, int.MaxValue - 4);
			Helper.CheckRange("iterations", iterations, 1, int.MaxValue);
			if (hmacAlgorithm.OutputSize == 0)
			{ throw new ArgumentException("Unsupported hash size.", "hmacAlgorithm"); }

			int hmacLength = hmacAlgorithm.OutputSize;
			_saltBuffer = new byte[salt.Length + 4]; Array.Copy(salt, _saltBuffer, salt.Length);
			_iterations = iterations; _hmacAlgorithm = hmacAlgorithm;
			_digest = new byte[hmacLength]; _digestT1 = new byte[hmacLength];
		}

		/// <summary>
		/// Reads from the derived key stream.
		/// </summary>
		/// <param name="count">The number of bytes to read.</param>
		/// <returns>Bytes from the derived key stream.</returns>
		public byte[] Read(int count)
		{
			Helper.CheckRange("count", count, 0, int.MaxValue);

			byte[] buffer = new byte[count];
			int bytes = Read(buffer, 0, count);
			if (bytes < count)
			{
				throw new ArgumentException("Can only return " + bytes + " bytes.", "count");
			}

			return buffer;
		}

		/// <summary>
		/// Computes a derived key.
		/// </summary>
		/// <param name="hmacAlgorithm">
        ///     The HMAC primitive instance to use. Must be pre-initialised.
		/// </param>
		/// <param name="salt">
		///     The salt.
		///     A unique salt means a unique derived key, even if the original key is identical.
		/// </param>
		/// <param name="iterations">The number of iterations to apply.</param>
		/// <param name="derivedKeyLength">The desired length of the derived key.</param>
		/// <returns>The derived key.</returns>
		public static byte[] ComputeDerivedKey(IMac hmacAlgorithm, byte[] salt, int iterations,
			int derivedKeyLength)
		{
			Helper.CheckRange("derivedKeyLength", derivedKeyLength, 0, int.MaxValue);

			using (Pbkdf2 kdf = new Pbkdf2(hmacAlgorithm, salt, iterations))
			{
				return kdf.Read(derivedKeyLength);
			}
		}

		/// <summary>
		/// Closes the stream, clearing memory and disposing of the HMAC algorithm.
		/// </summary>
		protected override void Dispose (bool disposing) {
			try {
				if(disposing) {
					Array.Clear(_saltBuffer, 0, _saltBuffer.Length);
					Array.Clear(_digest, 0, _digest.Length);
					Array.Clear(_digestT1, 0, _digestT1.Length);
					_hmacAlgorithm.Reset ();
				}
			} finally {
				base.Dispose (disposing);
			}
		}

		public override void Close () {
			this.Dispose (true);
			GC.SuppressFinalize (this);
		}

		void ComputeBlock(uint pos)
		{
			pos.ToBigEndian_NoChecks(_saltBuffer, _saltBuffer.Length - 4);
			ComputeHmac(_saltBuffer, _digestT1);
			Array.Copy(_digestT1, _digest, _digestT1.Length);

			for (int i = 1; i < _iterations; i++)
			{
				ComputeHmac(_digestT1, _digestT1);
				for (int j = 0; j < _digest.Length; j++) { _digest[j] ^= _digestT1[j]; }
			}

			Array.Clear(_digestT1, 0, _digestT1.Length);
		}

		void ComputeHmac(byte[] input, byte[] output)
		{
			_hmacAlgorithm.Reset ();
			_hmacAlgorithm.BlockUpdate (input, 0, input.Length);
			_hmacAlgorithm.DoFinal (output, 0);
		}
		#endregion

		#region Stream
		long _blockStart, _blockEnd, _pos;

		/// <exclude />
		public override void Flush()
		{

		}

		/// <inheritdoc />
		public override int Read(byte[] buffer, int offset, int count)
		{
			//Check.Bounds("buffer", buffer, offset, count); 
			int bytes = 0;

			while (count > 0)
			{
				if (Position < _blockStart || Position >= _blockEnd)
				{
					if (Position >= Length) { break; }

					long pos = Position / _digest.Length;
					ComputeBlock((uint)(pos + 1));
					_blockStart = pos * _digest.Length;
					_blockEnd = _blockStart + _digest.Length;
				}

				int bytesSoFar = (int)(Position - _blockStart);
				int bytesThisTime = (int)Math.Min(_digest.Length - bytesSoFar, count);
                _digest.CopyBytes_NoChecks(bytesSoFar, buffer, bytes, bytesThisTime);
				count -= bytesThisTime; bytes += bytesThisTime; Position += bytesThisTime;
			}

			return bytes;
		}

		/// <inheritdoc />
		public override long Seek(long offset, SeekOrigin origin)
		{
			long pos;

			switch (origin)
			{
			case SeekOrigin.Begin: pos = offset; break;
			case SeekOrigin.Current: pos = Position + offset; break;
			case SeekOrigin.End: pos = Length + offset; break;
			default: throw new ArgumentOutOfRangeException("origin", "Unknown seek type.");
			}

			if (pos < 0) { throw new ArgumentException("Can't seek before the stream start.", "offset"); }
			Position = pos; return pos;
		}

		/// <exclude />
		public override void SetLength(long value)
		{
			throw new NotSupportedException ();
		}

		/// <exclude />
		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException ();
		}

		/// <exclude />
		public override bool CanRead
		{
			get { return true; }
		}

		/// <exclude />
		public override bool CanSeek
		{
			get { return true; }
		}

		/// <exclude />
		public override bool CanWrite
		{
			get { return false; }
		}

		/// <summary>
		/// The maximum number of bytes that can be derived is 2^32-1 times the HMAC size.
		/// </summary>
		public override long Length
		{
			get { return (long)_digest.Length * uint.MaxValue; }
		}

		/// <summary>
		/// The position within the derived key stream.
		/// </summary>
		public override long Position
		{
			get { return _pos; }
			set
			{
				if (_pos < 0) { throw new ArgumentException("Can't seek before the stream start."); }
				_pos = value;
			}
		}
		#endregion
	}
}

