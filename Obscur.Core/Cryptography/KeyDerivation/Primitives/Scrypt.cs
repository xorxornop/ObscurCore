#region Licenses

// 	Copyright 2013-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

// Modified from CryptSharp code, license:

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


#endregion

using System;
using System.Threading;
using BitManipulator;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.Ciphers.Stream.Primitives;
using PerfCopy;

namespace Obscur.Core.Cryptography.KeyDerivation.Primitives
{
    public static class Scrypt
    {
        /// <summary>
        ///     Computes a derived key.
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
        ///     This is limited by the <paramref name="parallel" /> value.
        ///     <c>null</c> will use as many threads as possible.
        /// </param>
        /// <param name="derivedKeyLength">The desired length of the derived key.</param>
        /// <returns>The derived key.</returns>
        public static byte[] ComputeDerivedKey(byte[] key, byte[] salt,
            int cost, int blockSize, int parallel, int? maxThreads,
            int derivedKeyLength)
        {
            Helper.CheckRange("derivedKeyLength", derivedKeyLength, 0, int.MaxValue);

            using (Pbkdf2 kdf = GetStream(key, salt, cost, blockSize, parallel, maxThreads)) {
                return kdf.Read(derivedKeyLength);
            }
        }

        /// <summary>
        ///     The SCrypt algorithm creates a salt which it then uses as a one-iteration
        ///     PBKDF2 key stream with SHA256 HMAC. This method lets you retrieve this intermediate salt.
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
        ///     This is limited by the <paramref name="parallel" /> value.
        ///     <c>null</c> will use as many threads as possible.
        /// </param>
        /// <returns>The effective salt.</returns>
        public static byte[] GetEffectivePbkdf2Salt(byte[] key, byte[] salt,
            int cost, int blockSize, int parallel, int? maxThreads)
        {
            Helper.CheckNull("key", key);
            Helper.CheckNull("salt", salt);
            return MFcrypt(key, salt, cost, blockSize, parallel, maxThreads);
        }

        /// <summary>
        ///     Creates a derived key stream from which a derived key can be read.
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
        ///     This is limited by the <paramref name="parallel" /> value.
        ///     <c>null</c> will use as many threads as possible.
        /// </param>
        /// <returns>The derived key stream.</returns>
        public static Pbkdf2 GetStream(byte[] key, byte[] salt,
            int cost, int blockSize, int parallel, int? maxThreads)
        {
            byte[] B = GetEffectivePbkdf2Salt(key, salt, cost, blockSize, parallel, maxThreads);
            IMac hmac = AuthenticatorFactory.CreateHmacPrimitive(HashFunction.Sha256, key, null);
            var kdf = new Pbkdf2(hmac, B, 1);
            //Security.Clear(B);
            Array.Clear(B, 0, B.Length);
            return kdf;
        }

        private static byte[] MFcrypt(byte[] P, byte[] S,
            int cost, int blockSize, int parallel, int? maxThreads)
        {
            int MFLen = blockSize * 128;
            if (maxThreads == null) {
                maxThreads = int.MaxValue;
            }

            if (!(cost > 0 && cost % 2 == 0)) {
                throw new ArgumentOutOfRangeException("cost", "Cost must be a positive power of 2.");
            }
            Helper.CheckRange("blockSize", blockSize, 1, int.MaxValue / 128);
            Helper.CheckRange("parallel", parallel, 1, int.MaxValue / MFLen);
            Helper.CheckRange("maxThreads", (int) maxThreads, 1, int.MaxValue);

            IMac hmac = AuthenticatorFactory.CreateHmacPrimitive(HashFunction.Sha256, P);
            byte[] B = Pbkdf2.ComputeDerivedKey(hmac, S, 1, parallel * MFLen);

            var B0 = new uint[B.Length / sizeof(uint)];
            for (int i = 0; i < B0.Length; i++) {
                B0[i] = B.LittleEndianToUInt32_NoChecks(i * sizeof(uint));
            } // code is easier with uint[]

            ThreadSMixCalls(B0, MFLen, cost, blockSize, parallel, (int) maxThreads);
            for (int i = 0; i < B0.Length; i++) {
                B0[i].ToLittleEndian_NoChecks(B, i * sizeof(uint));
            }
            B0.SecureWipe();

            return B;
        }

        private static void ThreadSMixCalls(uint[] B0, int MFLen,
            int cost, int blockSize, int parallel, int maxThreads)
        {
            int threadCount = Math.Max(1, Math.Min(Environment.ProcessorCount, Math.Min(maxThreads, parallel)));
            const int defaultStackSize = 8192;
            int threadStackSize;
#if INCLUDE_UNSAFE
            const int maxStackSize = 32768;
            int Bs = 16 * 2 * blockSize;
            int SMixAllocationSize = ((Bs * 3) + 32 + cost) * sizeof(uint);
            Func<int, int> ceilPowOf2 = x => {
                var result = 2;
                while (result < x) {
                    result <<= 1;
                }
                return result;
            };

            threadStackSize = Math.Min(1024, ceilPowOf2(SMixAllocationSize));
            if (threadStackSize > maxStackSize) {
                threadStackSize = defaultStackSize;
            }
#else
            threadStackSize = defaultStackSize;
#endif

            int current = 0;
            ThreadStart workerThread = delegate
            {
                while (true) {
                    int j = Interlocked.Increment(ref current) - 1;
                    if (j >= parallel) {
                        break;
                    }
#if INCLUDE_UNSAFE
                    if (threadStackSize <= maxStackSize) {
                        SMixUnsafe(B0, j * MFLen / sizeof (uint), B0, j * MFLen / sizeof (uint), (uint) cost, blockSize);
                    } else {
                        SMix(B0, j * MFLen / sizeof(uint), B0, j * MFLen / sizeof(uint), (uint)cost, blockSize);
                    }
#else
                    SMix(B0, j * MFLen / sizeof(uint), B0, j * MFLen / sizeof(uint), (uint)cost, blockSize);
#endif
                }
            };

            var threads = new Thread[threadCount - 1];
            for (int i = 0; i < threads.Length; i++) {
                (threads[i] = new Thread(workerThread, threadStackSize)).Start();
            }
            workerThread();
            for (int i = 0; i < threads.Length; i++) {
                threads[i].Join();
            }
        }

        private static void SMix(uint[] B, int Boffset, uint[] Bp, int Bpoffset, uint N, int r)
        {
            uint Nmask = N - 1;
            int Bs = 16 * 2 * r;
            uint[] scratch1 = new uint[16]/*, scratch2 = new uint[16]*/;
            uint[] scratchX = new uint[16], scratchY = new uint[Bs];
            uint[] scratchZ = new uint[Bs];

            uint[] x = new uint[Bs];
            uint[][] v = new uint[N][];
            for (int i = 0; i < v.Length; i++) {
                v[i] = new uint[Bs];
            }

            B.DeepCopy_NoChecks(Boffset, x, 0, Bs);
            for (uint i = 0; i < N; i++) {
                x.DeepCopy_NoChecks(0, v[i], 0, Bs);
                BlockMix(x, 0, x, 0, scratchX, scratchY, scratch1, /*scratch2,*/ r);
            }
            for (uint i = 0; i < N; i++) {
                uint j = x[Bs - 16] & Nmask;
                uint[] vj = v[j];
                for (int k = 0; k < scratchZ.Length; k++) {
                    scratchZ[k] = x[k] ^ vj[k];
                }
                BlockMix(scratchZ, 0, x, 0, scratchX, scratchY, scratch1, /*scratch2,*/ r);
            }
            x.DeepCopy_NoChecks(0, Bp, Bpoffset, Bs);

            //for (int i = 0; i < v.Length; i++) {
            //    Clear(v[i]);
            //}
            //Clear(v);
            x.SecureWipe();
            scratchX.SecureWipe();
            scratchY.SecureWipe();
            scratchZ.SecureWipe();
            scratch1.SecureWipe();
            //scratch2.SecureWipe();
        }

        private static void BlockMix
            (uint[] B, // 16*2*r
             int Boffset,
             uint[] Bp, // 16*2*r
             int Bpoffset,
             uint[] x, // 16
             uint[] y, // 16*2*r -- unnecessary but it allows us to alias B and Bp
             uint[] scratch1, // 16
             /*uint[] scratch2, // 16 */
             int r)
        {
            int k = Boffset, m = 0, n = 16 * r;
            Array.Copy(B, (2 * r - 1) * 16, x, 0, 16);

            for (int i = 0; i < r; i++) {
                for (int j = 0; j < scratch1.Length; j++) {
                    scratch1[j] = x[j] ^ B[j + k];
                }
                XSalsa20Engine.HSalsa(8, scratch1, 0, x, 0);

                Array.Copy(x, 0, y, m, 16);
                k += 16;

                for (int j = 0; j < scratch1.Length; j++) {
                    scratch1[j] = x[j] ^ B[j + k];
                }
                XSalsa20Engine.HSalsa(8, scratch1, 0, x, 0);

                Array.Copy(x, 0, y, m + n, 16);
                k += 16;

                m += 16;
            }

            y.DeepCopy_NoChecks(0, Bp, Bpoffset, y.Length);
        }

#if INCLUDE_UNSAFE
        private static void SMixUnsafe(uint[] B, int Boffset, uint[] Bp, int Bpoffset, uint N, int r)
        {
            unsafe {
                uint Nmask = N - 1;
                int Bs = 16 * 2 * r;
                uint* scratch1 = stackalloc uint[16] /*, scratch2 = stackalloc uint[16]*/;
                uint* scratchX = stackalloc uint[16], scratchY = stackalloc uint[Bs];
                uint* scratchZ = stackalloc uint[Bs];

                uint* x = stackalloc uint[Bs];
                var v = new uint[N][];
                for (int i = 0; i < v.Length; i++) {
                    v[i] = new uint[Bs];
                }

                CopyUints(B, Boffset, x, Bs);
                for (uint i = 0; i < N; i++) {
                    CopyUints(x, v[i], 0, Bs);
                    BlockMix(x, 0, x, 0, scratchX, scratchY, scratch1, /*scratch2,*/ r);
                }
                for (uint i = 0; i < N; i++) {
                    uint j = x[Bs - 16] & Nmask;
                    uint[] vj = v[j];
                    for (int k = 0; k < Bs; k++) {
                        scratchZ[k] = x[k] ^ vj[k];
                    }
                    BlockMix(scratchZ, 0, x, 0, scratchX, scratchY, scratch1, /*scratch2,*/ r);
                }
                CopyUints(x, Bp, Bpoffset, Bs);

                for (int i = 0; i < v.Length; i++) {
                    v[i].SecureWipe();
                }

                CryptographyExtensions.WipeMemory(x, Bs);
                CryptographyExtensions.WipeMemory(scratchX, 16);
                CryptographyExtensions.WipeMemory(scratchY, Bs);
                CryptographyExtensions.WipeMemory(scratchZ, Bs);
                CryptographyExtensions.WipeMemory(scratch1, 16);
                //CryptographyExtensions.WipeMemory(scratch2, 16);
            }
        }

        private static unsafe void BlockMix
            (uint* B, // 16*2*r
                int Boffset,
                uint* Bp, // 16*2*r
                uint Bpoffset,
                uint* x, // 16
                uint* y, // 16*2*r -- unnecessary but it allows us to alias B and Bp
                uint* scratch1, // 16
            /*uint* scratch2, // 16 */
                int r)
        {
            int k = Boffset, m = 0, n = 16 * r;
            CopyExtensions.CopyMemory((byte*)(B + ((2 * r - 1) * 16)), (byte*)x, 16 * sizeof(uint));

            for (int i = 0; i < r; i++) {
                for (int j = 0; j < 16; j++) {
                    scratch1[j] = x[j] ^ B[j + k];
                }
                XSalsa20Engine.HSalsaUnsafe(8, scratch1, x);

                CopyExtensions.CopyMemory((byte*)x, (byte*)(y + m), 16 * sizeof(uint));

                k += 16;

                for (int j = 0; j < 16; j++) {
                    scratch1[j] = x[j] ^ B[j + k];
                }
                XSalsa20Engine.HSalsaUnsafe(8, scratch1, x);

                CopyExtensions.CopyMemory((byte*)x, (byte*)(y + m + n), 16 * sizeof(uint));
                k += 16;

                m += 16;
            }

            CopyExtensions.CopyMemory((byte*)y, (byte*)(Bp + Bpoffset), n * 2 * sizeof(uint));
        }

        private static unsafe void CopyUints(uint[] src, int srcOffset, uint* dst, int length)
        {
            for (int i = 0; i < length; i++) {
                dst[i] = src[srcOffset + i];
            }
        }

        private static unsafe void CopyUints(uint* src, uint[] dst, int dstOffset, int length)
        {
            for (int i = 0; i < length; i++) {
                dst[dstOffset + i] = src[i];
            }
        }
#endif
    }
}
