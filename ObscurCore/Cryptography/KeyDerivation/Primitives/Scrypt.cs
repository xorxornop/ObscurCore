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
using System.Threading;

namespace ObscurCore.Cryptography.KeyDerivation.Primitives
{
	public static class Scrypt
	{
		const int hLen = 32;

		/// <summary>
		/// Computes a derived key.
		/// </summary>
		/// <param name="key">The key to derive from.</param>
		/// <param name="salt">
		///     The salt.
		///     A unique salt means a unique SCrypt stream, even if the original key is identical.
		/// </param>
		/// <param name="cost">
		///     The cost parameter, typically a fairly large number such as 262144.
		///     Memory usage and CPU time scale approximately linearly with this parameter.
		/// </param>
		/// <param name="blockSize">
		///     The mixing block size, typically 8.
		///     Memory usage and CPU time scale approximately linearly with this parameter.
		/// </param>
		/// <param name="parallel">
		///     The level of parallelism, typically 1.
		///     CPU time scales approximately linearly with this parameter.
		/// </param>
		/// <param name="maxThreads">
		///     The maximum number of threads to spawn to derive the key.
		///     This is limited by the <paramref name="parallel"/> value.
		///     <c>null</c> will use as many threads as possible.
		/// </param>
		/// <param name="derivedKeyLength">The desired length of the derived key.</param>
		/// <returns>The derived key.</returns>
		public static byte[] ComputeDerivedKey(byte[] key, byte[] salt,
			int cost, int blockSize, int parallel, int? maxThreads,
			int derivedKeyLength)
		{
			Helper.CheckRange("derivedKeyLength", derivedKeyLength, 0, int.MaxValue);

			using (Pbkdf2 kdf = GetStream(key, salt, cost, blockSize, parallel, maxThreads))
			{
				return kdf.Read(derivedKeyLength);
			}
		}

		/// <summary>
		/// The SCrypt algorithm creates a salt which it then uses as a one-iteration
		/// PBKDF2 key stream with SHA256 HMAC. This method lets you retrieve this intermediate salt.
		/// </summary>
		/// <param name="key">The key to derive from.</param>
		/// <param name="salt">
		///     The salt.
		///     A unique salt means a unique SCrypt stream, even if the original key is identical.
		/// </param>
		/// <param name="cost">
		///     The cost parameter, typically a fairly large number such as 262144.
		///     Memory usage and CPU time scale approximately linearly with this parameter.
		/// </param>
		/// <param name="blockSize">
		///     The mixing block size, typically 8.
		///     Memory usage and CPU time scale approximately linearly with this parameter.
		/// </param>
		/// <param name="parallel">
		///     The level of parallelism, typically 1.
		///     CPU time scales approximately linearly with this parameter.
		/// </param>
		/// <param name="maxThreads">
		///     The maximum number of threads to spawn to derive the key.
		///     This is limited by the <paramref name="parallel"/> value.
		///     <c>null</c> will use as many threads as possible.
		/// </param>
		/// <returns>The effective salt.</returns>
		public static byte[] GetEffectivePbkdf2Salt(byte[] key, byte[] salt,
			int cost, int blockSize, int parallel, int? maxThreads)
		{
			Helper.CheckNull("key", key); Helper.CheckNull("salt", salt);
			return MFcrypt(key, salt, cost, blockSize, parallel, maxThreads);
		}

		/// <summary>
		/// Creates a derived key stream from which a derived key can be read.
		/// </summary>
		/// <param name="key">The key to derive from.</param>
		/// <param name="salt">
		///     The salt.
		///     A unique salt means a unique scrypt stream, even if the original key is identical.
		/// </param>
		/// <param name="cost">
		///     The cost parameter, typically a fairly large number such as 262144.
		///     Memory usage and CPU time scale approximately linearly with this parameter.
		/// </param>
		/// <param name="blockSize">
		///     The mixing block size, typically 8.
		///     Memory usage and CPU time scale approximately linearly with this parameter.
		/// </param>
		/// <param name="parallel">
		///     The level of parallelism, typically 1.
		///     CPU time scales approximately linearly with this parameter.
		/// </param>
		/// <param name="maxThreads">
		///     The maximum number of threads to spawn to derive the key.
		///     This is limited by the <paramref name="parallel"/> value.
		///     <c>null</c> will use as many threads as possible.
		/// </param>
		/// <returns>The derived key stream.</returns>
		public static Pbkdf2 GetStream(byte[] key, byte[] salt,
			int cost, int blockSize, int parallel, int? maxThreads)
		{
			byte[] B = GetEffectivePbkdf2Salt(key, salt, cost, blockSize, parallel, maxThreads);
			var hmac = Source.CreateHmacPrimitive (ObscurCore.Cryptography.Authentication.HashFunction.Sha256, key, null);
			Pbkdf2 kdf = new Pbkdf2(hmac, B, 1);
			//Security.Clear(B);
			Array.Clear (B, 0, B.Length);
			return kdf;
		}

		static byte[] MFcrypt(byte[] P, byte[] S,
			int cost, int blockSize, int parallel, int? maxThreads)
		{
			int MFLen = blockSize * 128;
			if (maxThreads == null) { maxThreads = int.MaxValue; }

			if(!(cost > 0 && cost % 2 == 0))
			{ throw new ArgumentOutOfRangeException("cost", "Cost must be a positive power of 2."); }
			Helper.CheckRange("blockSize", blockSize, 1, int.MaxValue / 128);
			Helper.CheckRange("parallel", parallel, 1, int.MaxValue / MFLen);
			Helper.CheckRange("maxThreads", (int)maxThreads, 1, int.MaxValue);

			var hmac = Source.CreateHmacPrimitive (ObscurCore.Cryptography.Authentication.HashFunction.Sha256, P, null);
			byte[] B = Pbkdf2.ComputeDerivedKey(hmac, S, 1, parallel * MFLen);

			uint[] B0 = new uint[B.Length / 4];
			for (int i = 0; i < B0.Length; i++) { B0[i] = B.LittleEndianToUInt32 (i * 4); } // code is easier with uint[]
			ThreadSMixCalls(B0, MFLen, cost, blockSize, parallel, (int)maxThreads);
			for (int i = 0; i < B0.Length; i++) { B0[i].ToLittleEndian (B, i * 4); }
			Array.Clear (B0, 0, B0.Length);

			return B;
		}

		static void ThreadSMixCalls(uint[] B0, int MFLen,
			int cost, int blockSize, int parallel, int maxThreads)
		{
			int current = 0;
			ThreadStart workerThread = delegate()
			{
				while (true)
				{
					int j = Interlocked.Increment(ref current) - 1;
					if (j >= parallel) { break; }

					SMix(B0, j * MFLen / 4, B0, j * MFLen / 4, (uint)cost, blockSize);
				}
			};

			int threadCount = Math.Max(1, Math.Min(Environment.ProcessorCount, Math.Min(maxThreads, parallel)));
			Thread[] threads = new Thread[threadCount - 1];
			for (int i = 0; i < threads.Length; i++) { (threads[i] = new Thread(workerThread, 8192)).Start(); }
			workerThread();
			for (int i = 0; i < threads.Length; i++) { threads[i].Join(); }
		}

		static void SMix(uint[] B, int Boffset, uint[] Bp, int Bpoffset, uint N, int r)
		{
			uint Nmask = N - 1; int Bs = 16 * 2 * r;
			uint[] scratch1 = new uint[16];
			uint[] scratchX = new uint[16], scratchY = new uint[Bs];
			uint[] scratchZ = new uint[Bs];

			uint[] x = new uint[Bs]; uint[][] v = new uint[N][];
			for (int i = 0; i < v.Length; i++) { v[i] = new uint[Bs]; }

			Array.Copy(B, Boffset, x, 0, Bs);
			for (uint i = 0; i < N; i++)
			{
				Array.Copy(x, v[i], Bs);
				BlockMix(x, 0, x, 0, scratchX, scratchY, scratch1, r); 
			}
			for (uint i = 0; i < N; i++)
			{
				uint j = x[Bs - 16] & Nmask; uint[] vj = v[j];
				for (int k = 0; k < scratchZ.Length; k++) { scratchZ[k] = x[k] ^ vj[k]; }
				BlockMix(scratchZ, 0, x, 0, scratchX, scratchY, scratch1, r);
			}
			Array.Copy(x, 0, Bp, Bpoffset, Bs);

			for (int i = 0; i < v.Length; i++) { Array.Clear(v[i], 0, v[i].Length); }
			Array.Clear(v, 0, v.Length); Array.Clear(x, 0, x.Length);
			Array.Clear(scratchX, 0, scratchX.Length); Array.Clear(scratchY, 0, scratchY.Length); Array.Clear(scratchZ, 0, scratchZ.Length);
			Array.Clear(scratch1, 0, scratch1.Length);
		}

		static void BlockMix
		(uint[] B,        // 16*2*r
			int    Boffset,
			uint[] Bp,       // 16*2*r
			int    Bpoffset,
			uint[] x,        // 16
			uint[] y,        // 16*2*r -- unnecessary but it allows us to alias B and Bp
			uint[] scratch,  // 16
			int r)
		{
			int k = Boffset, m = 0, n = 16 * r;
			Array.Copy(B, (2 * r - 1) * 16, x, 0, 16);

			for (int i = 0; i < r; i++)
			{
				for (int j = 0; j < scratch.Length; j++) { scratch[j] = x[j] ^ B[j + k]; }
				ObscurCore.Cryptography.Ciphers.Stream.Primitives.Salsa20Engine.Salsa(8, scratch, 0, x, 0);
				Array.Copy(x, 0, y, m, 16);
				k += 16;

				for (int j = 0; j < scratch.Length; j++) { scratch[j] = x[j] ^ B[j + k]; }
				ObscurCore.Cryptography.Ciphers.Stream.Primitives.Salsa20Engine.Salsa(8, scratch, 0, x, 0);
				Array.Copy(x, 0, y, m + n, 16);
				k += 16;

				m += 16;
			}

			Array.Copy(y, 0, Bp, Bpoffset, y.Length);
		}
	}
}

