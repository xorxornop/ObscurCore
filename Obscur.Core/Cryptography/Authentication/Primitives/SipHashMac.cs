using System;
using Obscur.Core.Cryptography.Support;

namespace Obscur.Core.Cryptography.Authentication.Primitives
{
	/// <summary>
	/// Implementation of SipHash as specified in "SipHash: a fast short-input PRF", by Jean-Philippe
	/// Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf).
	/// </summary>
	/// <remarks>
	/// "SipHash is a family of PRFs SipHash-c-d where the integer parameters c and d are the number of
	/// compression rounds and the number of finalization rounds. A compression round is identical to a
	/// finalization round and this round function is called SipRound. Given a 128-bit key k and a
	/// (possibly empty) byte string m, SipHash-c-d returns a 64-bit value..."
	/// </remarks>
	public class SipHash
		: IMac
	{
		protected readonly int c, d;

		protected long k0, k1;
		protected long v0, v1, v2, v3, v4;

		protected byte[] buf = new byte[8];
		protected int bufPos = 0;
		protected int wordCount = 0;

		/// <summary>SipHash-2-4</summary>
		public SipHash()
			: this(2, 4)
		{
		}

		/// <summary>SipHash-c-d</summary>
		/// <param name="c">the number of compression rounds</param>
		/// <param name="d">the number of finalization rounds</param>
		public SipHash(int c, int d)
		{
			this.c = c;
			this.d = d;
		}

		public virtual string AlgorithmName
		{
			get { return "SipHash-" + c + "-" + d; }
		}

        /// <summary>
        ///     Enumerated function identity.
        /// </summary>
        public HashFunction Identity { get { return MacFunction.Blake2B256; } }

		public virtual int OutputSize
		{
			get { return 8; }
		}

		public void Init (byte[] key) {
			if (key == null)
				throw new ArgumentException("must be an instance of KeyParameter", "parameters");
			if (key.Length != 16)
				throw new ArgumentException("must be a 128-bit key", "parameters");

			this.k0 = (long)key.LittleEndianToUInt64 (0);
			this.k1 = (long)key.LittleEndianToUInt64 (8);

			Reset();
		}

		public virtual void Update(byte input)
		{
			buf[bufPos] = input;
			if (++bufPos == buf.Length)
			{
				ProcessMessageWord();
				bufPos = 0;
			}
		}

		public virtual void BlockUpdate(byte[] input, int offset, int length)
		{
			for (int i = 0; i < length; ++i)
			{
				buf[bufPos] = input[offset + i];
				if (++bufPos == buf.Length)
				{
					ProcessMessageWord();
					bufPos = 0;
				}
			}
		}

		public virtual long DoFinal()
		{
			buf[7] = (byte)((wordCount << 3) + bufPos);
			while (bufPos < 7)
			{
				buf[bufPos++] = 0;
			}

			ProcessMessageWord();

			v2 ^= 0xffL;

			ApplySipRounds(d);

			long result = v0 ^ v1 ^ v2 ^ v3;

			Reset();

			return result;
		}

		public virtual int DoFinal(byte[] output, int outOff)
		{
			long result = DoFinal();
			Pack.UInt64_To_LE((ulong)result, output, outOff);
			return 8;
		}

		public virtual void Reset()
		{
			v0 = k0 ^ 0x736f6d6570736575L;
			v1 = k1 ^ 0x646f72616e646f6dL;
			v2 = k0 ^ 0x6c7967656e657261L;
			v3 = k1 ^ 0x7465646279746573L;

			Array.Clear(buf, 0, buf.Length);
			bufPos = 0;
			wordCount = 0;
		}

		protected virtual void ProcessMessageWord()
		{
			++wordCount;
			long m = (long)Pack.LE_To_UInt64(buf, 0);
			v3 ^= m;
			ApplySipRounds(c);
			v0 ^= m;
		}

		protected virtual void ApplySipRounds(int n)
		{
			for (int r = 0; r < n; ++r)
			{
				v0 += v1;
				v2 += v3;
				v1 = v1.RotateLeft(13);
                v3 = v3.RotateLeft(16);
				v1 ^= v0;
				v3 ^= v2;
                v0 = v0.RotateLeft(32);
				v2 += v1;
				v0 += v3;
                v1 = v1.RotateLeft(17);
                v3 = v3.RotateLeft(21);
				v1 ^= v2;
				v3 ^= v0;
                v2 = v2.RotateLeft(32);
			}
		}
	}
}

