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
using BitManipulator;
using Obscur.Core.Cryptography.Entropy;
using PerfCopy;

namespace Obscur.Core.Cryptography.Ciphers.Stream.Primitives
{
    /// <summary>
    /// SOSEMANUK stream cipher implementation.
    /// </summary>
    public sealed class SosemanukEngine : StreamCipherEngine, ICsPrngCompatible
    {
		private const int BufferLen = 80;

		/// <summary>
		/// Internal buffer for partial blocks.
		/// </summary>
		private byte[] _streamBuf = new byte[BufferLen];

		/// <summary>
		/// Points to the first stream byte which 
		/// has been computed but not output.
		/// </summary>
		private int _streamPtr = BufferLen;

        // Stores engine state
        private uint lfsr0, lfsr1, lfsr2, lfsr3, lfsr4;
        private uint lfsr5, lfsr6, lfsr7, lfsr8, lfsr9;
        private uint fsmR1, fsmR2;
		// Subkeys for Serpent24: 100 32-bit words.
		private uint[] _serpent24SubKeys = new uint[100];

        public SosemanukEngine()
            : base(StreamCipher.Sosemanuk)
	    {
	    }

        protected override void InitState()
        {
            KeySetup(Key);
            IVSetup(Nonce);
            IsInitialised = true;
        }

        /// <inheritdoc />
		public override int StateSize
		{
			get { return BufferLen; }
		}

        /// <inheritdoc />
        public override void Reset () {
            KeySetup(Key);
            IVSetup(Nonce);
            IsInitialised = true;
        }

        /// <inheritdoc />
        public override byte ReturnByte (byte input) {
            if (!IsInitialised) 
				throw new InvalidOperationException (AlgorithmName + " not initialised.");
		
			if (_streamPtr == BufferLen) {
				MakeStreamBlock (_streamBuf, 0);
				_streamPtr = 0;
			}
			return (byte)(input ^ _streamBuf[_streamPtr++]);
        }

        protected internal override void ProcessBytesInternal(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            // Any left over from last time?
            if (_streamPtr < BufferLen) {
                var blen = BufferLen - _streamPtr;
                if (blen > length)
                    blen = length;
                input.XorInternal(inOff, _streamBuf, _streamPtr, output, outOff, blen);
                _streamPtr += blen;
                inOff += blen;
                outOff += blen;
                length -= blen;
            }

            int remainder;
            var blocks = Math.DivRem(length, BufferLen, out remainder);

#if INCLUDE_UNSAFE
            unsafe {
                fixed (byte* inPtr = input) {
                    fixed (byte* outPtr = output) {
                        for (var i = 0; i < blocks; i++) {
                            ProcessStride(inPtr + inOff + (BufferLen * i), 
                                outPtr + outOff + (BufferLen * i));
                        }
                    }
                }
            }
            inOff += BufferLen * blocks;
            outOff += BufferLen * blocks;
#else
            for (var i = 0; i < blocks; i++) {
                MakeStreamBlock(_streamBuf, 0);
                input.XorInternal(inOff, _streamBuf, 0, output, outOff, BufferLen);
                inOff += BufferLen;
                outOff += BufferLen;
            }
#endif

            if (remainder > 0) {
                MakeStreamBlock(_streamBuf, 0);
                input.XorInternal(inOff, _streamBuf, 0, output, outOff, remainder);
                _streamPtr = remainder;
            }
        }

        public void GetKeystream(byte[] buffer, int offset, int len) {
            if (!IsInitialised) throw new InvalidOperationException(AlgorithmName + " not initialised.");
			if ((offset + len) > buffer.Length) 
				throw new ArgumentException("Output buffer too short.");

            GenerateKeystream(buffer, offset, len);
        }

        #region Private implementation

		private static uint[] MulAlpha = new uint[256];
        private static uint[] DivAlpha = new uint[256];

        static SosemanukEngine() {
            /*
             * We first build exponential and logarithm tables
             * relatively to beta in F_{2^8}. We set log(0x00) = 0xFF
             * conventionaly, but this is actually not used in our
             * computations.
             */
			uint[] expb = new uint[256];
			for (uint i = 0, x = 0x01; i < 0xFF; i++) {
                expb[i] = x;
                x <<= 1;
                if (x > 0xFF)
                    x ^= 0x1A9;
            }
            expb[0xFF] = 0x00;
			uint[] logb = new uint[256];
            for (var i = 0; i < 0x100; i++)
				logb[expb[i]] = (uint)i;

            /*
             * We now compute mulAlpha[] and divAlpha[]. For all
             * x != 0, we work with invertible numbers, which are
             * as such powers of beta. Multiplication (in F_{2^8})
             * is then implemented as integer addition modulo 255,
             * over the exponents computed by the logb[] table.
             *
             * We have the following equations:
             * alpha^4 = beta^23 * alpha^3 + beta^245 * alpha^2
             *           + beta^48 * alpha + beta^239
             * 1/alpha = beta^16 * alpha^3 + beta^39 * alpha^2
             *           + beta^6 * alpha + beta^64
             */
            MulAlpha[0x00] = 0x00000000;
            DivAlpha[0x00] = 0x00000000;
            for (uint x = 1; x < 0x100; x++) {
                uint ex = logb[x];
                MulAlpha[x] = (expb[(ex + 23) % 255] << 24)
                    | (expb[(ex + 245) % 255] << 16)
                    | (expb[(ex + 48) % 255] << 8)
                    | expb[(ex + 239) % 255];
                DivAlpha[x] = (expb[(ex + 16) % 255] << 24)
                    | (expb[(ex + 39) % 255] << 16)
                    | (expb[(ex + 6) % 255] << 8)
                    | expb[(ex + 64) % 255];
            }
        }

        private void GenerateKeystream (byte[] buf, int off, int len) {
            if (_streamPtr < BufferLen) {
                var blen = BufferLen - _streamPtr;
                if (blen > len)
                    blen = len;
                _streamBuf.DeepCopy_NoChecks(_streamPtr, buf, off, blen);
                _streamPtr += blen;
                off += blen;
                len -= blen;
            }
            while (len > 0) {
                if (len >= BufferLen) {
                    MakeStreamBlock(buf, off);
                    off += BufferLen;
                    len -= BufferLen;
                } else {
                    MakeStreamBlock(_streamBuf, 0);
                    _streamBuf.DeepCopy_NoChecks(0, buf, off, len);
                    _streamPtr = len;
                    len = 0;
                }
            }
        }

        private void MakeStreamBlock (byte[] buf, int off)
	    {
		    uint s0 = lfsr0;
		    uint s1 = lfsr1;
		    uint s2 = lfsr2;
		    uint s3 = lfsr3;
		    uint s4 = lfsr4;
		    uint s5 = lfsr5;
		    uint s6 = lfsr6;
		    uint s7 = lfsr7;
		    uint s8 = lfsr8;
		    uint s9 = lfsr9;
		    uint r1 = fsmR1;
		    uint r2 = fsmR2;
		    uint f0, f1, f2, f3, f4;
		    uint v0, v1, v2, v3;
		    uint tt;

		    tt = r1;
		    r1 = r2 + (s1 ^ ((r1 & 0x01) != 0 ? s8 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v0 = s0;
		    s0 = ((s0 << 8) ^ MulAlpha[s0 >> 24])
			    ^ ((s3 >> 8) ^ DivAlpha[s3 & 0xFF]) ^ s9;
		    f0 = (s9 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v1 = s1;
		    s1 = ((s1 << 8) ^ MulAlpha[s1 >> 24])
			    ^ ((s4 >> 8) ^ DivAlpha[s4 & 0xFF]) ^ s0;
		    f1 = (s0 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s3 ^ ((r1 & 0x01) != 0 ? s0 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v2 = s2;
		    s2 = ((s2 << 8) ^ MulAlpha[s2 >> 24])
			    ^ ((s5 >> 8) ^ DivAlpha[s5 & 0xFF]) ^ s1;
		    f2 = (s1 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v3 = s3;
		    s3 = ((s3 << 8) ^ MulAlpha[s3 >> 24])
			    ^ ((s6 >> 8) ^ DivAlpha[s6 & 0xFF]) ^ s2;
		    f3 = (s2 + r1) ^ r2;

		    /*
		     * Apply the third S-box (number 2) on (f3, f2, f1, f0).
		     */
		    f4 = f0;
		    f0 &= f2;
		    f0 ^= f3;
		    f2 ^= f1;
		    f2 ^= f0;
		    f3 |= f4;
		    f3 ^= f1;
		    f4 ^= f2;
		    f1 = f3;
		    f3 |= f4;
		    f3 ^= f0;
		    f0 &= f1;
		    f4 ^= f0;
		    f1 ^= f3;
		    f1 ^= f4;
		    f4 = ~f4;

		    /*
		     * S-box result is in (f2, f3, f1, f4).
		     */
			(f2 ^ v0).ToLittleEndian (buf, off);
			(f3 ^ v1).ToLittleEndian (buf, off + 4);
			(f1 ^ v2).ToLittleEndian (buf, off + 8);
			(f4 ^ v3).ToLittleEndian (buf, off + 12);

		    tt = r1;
		    r1 = r2 + (s5 ^ ((r1 & 0x01) != 0 ? s2 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v0 = s4;
		    s4 = ((s4 << 8) ^ MulAlpha[s4 >> 24])
			    ^ ((s7 >> 8) ^ DivAlpha[s7 & 0xFF]) ^ s3;
		    f0 = (s3 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v1 = s5;
		    s5 = ((s5 << 8) ^ MulAlpha[s5 >> 24])
			    ^ ((s8 >> 8) ^ DivAlpha[s8 & 0xFF]) ^ s4;
		    f1 = (s4 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s7 ^ ((r1 & 0x01) != 0 ? s4 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v2 = s6;
		    s6 = ((s6 << 8) ^ MulAlpha[s6 >> 24])
			    ^ ((s9 >> 8) ^ DivAlpha[s9 & 0xFF]) ^ s5;
		    f2 = (s5 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v3 = s7;
		    s7 = ((s7 << 8) ^ MulAlpha[s7 >> 24])
			    ^ ((s0 >> 8) ^ DivAlpha[s0 & 0xFF]) ^ s6;
		    f3 = (s6 + r1) ^ r2;

		    /*
		     * Apply the third S-box (number 2) on (f3, f2, f1, f0).
		     */
		    f4 = f0;
		    f0 &= f2;
		    f0 ^= f3;
		    f2 ^= f1;
		    f2 ^= f0;
		    f3 |= f4;
		    f3 ^= f1;
		    f4 ^= f2;
		    f1 = f3;
		    f3 |= f4;
		    f3 ^= f0;
		    f0 &= f1;
		    f4 ^= f0;
		    f1 ^= f3;
		    f1 ^= f4;
		    f4 = ~f4;

		    /*
		     * S-box result is in (f2, f3, f1, f4).
		     */
		    (f2 ^ v0).ToLittleEndian (buf, off + 16);
			(f3 ^ v1).ToLittleEndian (buf, off + 20);
			(f1 ^ v2).ToLittleEndian (buf, off + 24);
			(f4 ^ v3).ToLittleEndian (buf, off + 28);

		    tt = r1;
		    r1 = r2 + (s9 ^ ((r1 & 0x01) != 0 ? s6 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v0 = s8;
		    s8 = ((s8 << 8) ^ MulAlpha[s8 >> 24])
			    ^ ((s1 >> 8) ^ DivAlpha[s1 & 0xFF]) ^ s7;
		    f0 = (s7 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v1 = s9;
		    s9 = ((s9 << 8) ^ MulAlpha[s9 >> 24])
			    ^ ((s2 >> 8) ^ DivAlpha[s2 & 0xFF]) ^ s8;
		    f1 = (s8 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s1 ^ ((r1 & 0x01) != 0 ? s8 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v2 = s0;
		    s0 = ((s0 << 8) ^ MulAlpha[s0 >> 24])
			    ^ ((s3 >> 8) ^ DivAlpha[s3 & 0xFF]) ^ s9;
		    f2 = (s9 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v3 = s1;
		    s1 = ((s1 << 8) ^ MulAlpha[s1 >> 24])
			    ^ ((s4 >> 8) ^ DivAlpha[s4 & 0xFF]) ^ s0;
		    f3 = (s0 + r1) ^ r2;

		    /*
		     * Apply the third S-box (number 2) on (f3, f2, f1, f0).
		     */
		    f4 = f0;
		    f0 &= f2;
		    f0 ^= f3;
		    f2 ^= f1;
		    f2 ^= f0;
		    f3 |= f4;
		    f3 ^= f1;
		    f4 ^= f2;
		    f1 = f3;
		    f3 |= f4;
		    f3 ^= f0;
		    f0 &= f1;
		    f4 ^= f0;
		    f1 ^= f3;
		    f1 ^= f4;
		    f4 = ~f4;

		    /*
		     * S-box result is in (f2, f3, f1, f4).
		     */
		    (f2 ^ v0).ToLittleEndian (buf, off + 32);
			(f3 ^ v1).ToLittleEndian (buf, off + 36);
			(f1 ^ v2).ToLittleEndian (buf, off + 40);
			(f4 ^ v3).ToLittleEndian (buf, off + 44);

		    tt = r1;
		    r1 = r2 + (s3 ^ ((r1 & 0x01) != 0 ? s0 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v0 = s2;
		    s2 = ((s2 << 8) ^ MulAlpha[s2 >> 24])
			    ^ ((s5 >> 8) ^ DivAlpha[s5 & 0xFF]) ^ s1;
		    f0 = (s1 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v1 = s3;
		    s3 = ((s3 << 8) ^ MulAlpha[s3 >> 24])
			    ^ ((s6 >> 8) ^ DivAlpha[s6 & 0xFF]) ^ s2;
		    f1 = (s2 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s5 ^ ((r1 & 0x01) != 0 ? s2 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v2 = s4;
		    s4 = ((s4 << 8) ^ MulAlpha[s4 >> 24])
			    ^ ((s7 >> 8) ^ DivAlpha[s7 & 0xFF]) ^ s3;
		    f2 = (s3 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v3 = s5;
		    s5 = ((s5 << 8) ^ MulAlpha[s5 >> 24])
			    ^ ((s8 >> 8) ^ DivAlpha[s8 & 0xFF]) ^ s4;
		    f3 = (s4 + r1) ^ r2;

		    /*
		     * Apply the third S-box (number 2) on (f3, f2, f1, f0).
		     */
		    f4 = f0;
		    f0 &= f2;
		    f0 ^= f3;
		    f2 ^= f1;
		    f2 ^= f0;
		    f3 |= f4;
		    f3 ^= f1;
		    f4 ^= f2;
		    f1 = f3;
		    f3 |= f4;
		    f3 ^= f0;
		    f0 &= f1;
		    f4 ^= f0;
		    f1 ^= f3;
		    f1 ^= f4;
		    f4 = ~f4;

		    /*
		     * S-box result is in (f2, f3, f1, f4).
		     */
		    (f2 ^ v0).ToLittleEndian (buf, off + 48);
			(f3 ^ v1).ToLittleEndian (buf, off + 52);
			(f1 ^ v2).ToLittleEndian (buf, off + 56);
			(f4 ^ v3).ToLittleEndian (buf, off + 60);

		    tt = r1;
		    r1 = r2 + (s7 ^ ((r1 & 0x01) != 0 ? s4 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v0 = s6;
		    s6 = ((s6 << 8) ^ MulAlpha[s6 >> 24])
			    ^ ((s9 >> 8) ^ DivAlpha[s9 & 0xFF]) ^ s5;
		    f0 = (s5 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v1 = s7;
		    s7 = ((s7 << 8) ^ MulAlpha[s7 >> 24])
			    ^ ((s0 >> 8) ^ DivAlpha[s0 & 0xFF]) ^ s6;
		    f1 = (s6 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s9 ^ ((r1 & 0x01) != 0 ? s6 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v2 = s8;
		    s8 = ((s8 << 8) ^ MulAlpha[s8 >> 24])
			    ^ ((s1 >> 8) ^ DivAlpha[s1 & 0xFF]) ^ s7;
		    f2 = (s7 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
		    v3 = s9;
		    s9 = ((s9 << 8) ^ MulAlpha[s9 >> 24])
                ^ ( ( s2 >> 8) ^ DivAlpha[s2 & 0xFF]) ^ s8;
		    f3 = (s8 + r1) ^ r2;

		    /*
		     * Apply the third S-box (number 2) on (f3, f2, f1, f0).
		     */
		    f4 = f0;
		    f0 &= f2;
		    f0 ^= f3;
		    f2 ^= f1;
		    f2 ^= f0;
		    f3 |= f4;
		    f3 ^= f1;
		    f4 ^= f2;
		    f1 = f3;
		    f3 |= f4;
		    f3 ^= f0;
		    f0 &= f1;
		    f4 ^= f0;
		    f1 ^= f3;
		    f1 ^= f4;
		    f4 = ~f4;

		    /*
		     * S-box result is in (f2, f3, f1, f4).
		     */
		    (f2 ^ v0).ToLittleEndian (buf, off + 64);
			(f3 ^ v1).ToLittleEndian (buf, off + 68);
			(f1 ^ v2).ToLittleEndian (buf, off + 72);
			(f4 ^ v3).ToLittleEndian (buf, off + 76);

		    lfsr0 = s0;
		    lfsr1 = s1;
		    lfsr2 = s2;
		    lfsr3 = s3;
		    lfsr4 = s4;
		    lfsr5 = s5;
		    lfsr6 = s6;
		    lfsr7 = s7;
		    lfsr8 = s8;
		    lfsr9 = s9;
		    fsmR1 = r1;
		    fsmR2 = r2;
        }

#if INCLUDE_UNSAFE
        private unsafe void ProcessStride(byte* input, byte* output)
        {
            var inputUintPtr = (uint*)input;
            var outputUintPtr = (uint*)output;

            uint s0 = lfsr0;
            uint s1 = lfsr1;
            uint s2 = lfsr2;
            uint s3 = lfsr3;
            uint s4 = lfsr4;
            uint s5 = lfsr5;
            uint s6 = lfsr6;
            uint s7 = lfsr7;
            uint s8 = lfsr8;
            uint s9 = lfsr9;
            uint r1 = fsmR1;
            uint r2 = fsmR2;
            uint f0, f1, f2, f3, f4;
            uint v0, v1, v2, v3;
            uint tt;

            tt = r1;
            r1 = r2 + (s1 ^ ((r1 & 0x01) != 0 ? s8 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v0 = s0;
            s0 = ((s0 << 8) ^ MulAlpha[s0 >> 24])
                ^ ((s3 >> 8) ^ DivAlpha[s3 & 0xFF]) ^ s9;
            f0 = (s9 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v1 = s1;
            s1 = ((s1 << 8) ^ MulAlpha[s1 >> 24])
                ^ ((s4 >> 8) ^ DivAlpha[s4 & 0xFF]) ^ s0;
            f1 = (s0 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s3 ^ ((r1 & 0x01) != 0 ? s0 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v2 = s2;
            s2 = ((s2 << 8) ^ MulAlpha[s2 >> 24])
                ^ ((s5 >> 8) ^ DivAlpha[s5 & 0xFF]) ^ s1;
            f2 = (s1 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v3 = s3;
            s3 = ((s3 << 8) ^ MulAlpha[s3 >> 24])
                ^ ((s6 >> 8) ^ DivAlpha[s6 & 0xFF]) ^ s2;
            f3 = (s2 + r1) ^ r2;

            /*
             * Apply the third S-box (number 2) on (f3, f2, f1, f0).
             */
            f4 = f0;
            f0 &= f2;
            f0 ^= f3;
            f2 ^= f1;
            f2 ^= f0;
            f3 |= f4;
            f3 ^= f1;
            f4 ^= f2;
            f1 = f3;
            f3 |= f4;
            f3 ^= f0;
            f0 &= f1;
            f4 ^= f0;
            f1 ^= f3;
            f1 ^= f4;
            f4 = ~f4;

            /*
             * S-box result is in (f2, f3, f1, f4).
             */
            outputUintPtr[0] = (f2 ^ v0) ^ inputUintPtr[0];
            outputUintPtr[1] = (f3 ^ v1) ^ inputUintPtr[1];
            outputUintPtr[2] = (f1 ^ v2) ^ inputUintPtr[2];
            outputUintPtr[3] = (f4 ^ v3) ^ inputUintPtr[3];

            tt = r1;
            r1 = r2 + (s5 ^ ((r1 & 0x01) != 0 ? s2 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v0 = s4;
            s4 = ((s4 << 8) ^ MulAlpha[s4 >> 24])
                ^ ((s7 >> 8) ^ DivAlpha[s7 & 0xFF]) ^ s3;
            f0 = (s3 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v1 = s5;
            s5 = ((s5 << 8) ^ MulAlpha[s5 >> 24])
                ^ ((s8 >> 8) ^ DivAlpha[s8 & 0xFF]) ^ s4;
            f1 = (s4 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s7 ^ ((r1 & 0x01) != 0 ? s4 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v2 = s6;
            s6 = ((s6 << 8) ^ MulAlpha[s6 >> 24])
                ^ ((s9 >> 8) ^ DivAlpha[s9 & 0xFF]) ^ s5;
            f2 = (s5 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v3 = s7;
            s7 = ((s7 << 8) ^ MulAlpha[s7 >> 24])
                ^ ((s0 >> 8) ^ DivAlpha[s0 & 0xFF]) ^ s6;
            f3 = (s6 + r1) ^ r2;

            /*
             * Apply the third S-box (number 2) on (f3, f2, f1, f0).
             */
            f4 = f0;
            f0 &= f2;
            f0 ^= f3;
            f2 ^= f1;
            f2 ^= f0;
            f3 |= f4;
            f3 ^= f1;
            f4 ^= f2;
            f1 = f3;
            f3 |= f4;
            f3 ^= f0;
            f0 &= f1;
            f4 ^= f0;
            f1 ^= f3;
            f1 ^= f4;
            f4 = ~f4;

            /*
             * S-box result is in (f2, f3, f1, f4).
             */
            outputUintPtr[4] = (f2 ^ v0) ^ inputUintPtr[4];
            outputUintPtr[5] = (f3 ^ v1) ^ inputUintPtr[5];
            outputUintPtr[6] = (f1 ^ v2) ^ inputUintPtr[6];
            outputUintPtr[7] = (f4 ^ v3) ^ inputUintPtr[7];

            tt = r1;
            r1 = r2 + (s9 ^ ((r1 & 0x01) != 0 ? s6 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v0 = s8;
            s8 = ((s8 << 8) ^ MulAlpha[s8 >> 24])
                ^ ((s1 >> 8) ^ DivAlpha[s1 & 0xFF]) ^ s7;
            f0 = (s7 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v1 = s9;
            s9 = ((s9 << 8) ^ MulAlpha[s9 >> 24])
                ^ ((s2 >> 8) ^ DivAlpha[s2 & 0xFF]) ^ s8;
            f1 = (s8 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s1 ^ ((r1 & 0x01) != 0 ? s8 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v2 = s0;
            s0 = ((s0 << 8) ^ MulAlpha[s0 >> 24])
                ^ ((s3 >> 8) ^ DivAlpha[s3 & 0xFF]) ^ s9;
            f2 = (s9 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v3 = s1;
            s1 = ((s1 << 8) ^ MulAlpha[s1 >> 24])
                ^ ((s4 >> 8) ^ DivAlpha[s4 & 0xFF]) ^ s0;
            f3 = (s0 + r1) ^ r2;

            /*
             * Apply the third S-box (number 2) on (f3, f2, f1, f0).
             */
            f4 = f0;
            f0 &= f2;
            f0 ^= f3;
            f2 ^= f1;
            f2 ^= f0;
            f3 |= f4;
            f3 ^= f1;
            f4 ^= f2;
            f1 = f3;
            f3 |= f4;
            f3 ^= f0;
            f0 &= f1;
            f4 ^= f0;
            f1 ^= f3;
            f1 ^= f4;
            f4 = ~f4;

            /*
             * S-box result is in (f2, f3, f1, f4).
             */
            outputUintPtr[8] = (f2 ^ v0) ^ inputUintPtr[8];
            outputUintPtr[9] = (f3 ^ v1) ^ inputUintPtr[9];
            outputUintPtr[10] = (f1 ^ v2) ^ inputUintPtr[10];
            outputUintPtr[11] = (f4 ^ v3) ^ inputUintPtr[11];

            tt = r1;
            r1 = r2 + (s3 ^ ((r1 & 0x01) != 0 ? s0 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v0 = s2;
            s2 = ((s2 << 8) ^ MulAlpha[s2 >> 24])
                ^ ((s5 >> 8) ^ DivAlpha[s5 & 0xFF]) ^ s1;
            f0 = (s1 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v1 = s3;
            s3 = ((s3 << 8) ^ MulAlpha[s3 >> 24])
                ^ ((s6 >> 8) ^ DivAlpha[s6 & 0xFF]) ^ s2;
            f1 = (s2 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s5 ^ ((r1 & 0x01) != 0 ? s2 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v2 = s4;
            s4 = ((s4 << 8) ^ MulAlpha[s4 >> 24])
                ^ ((s7 >> 8) ^ DivAlpha[s7 & 0xFF]) ^ s3;
            f2 = (s3 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v3 = s5;
            s5 = ((s5 << 8) ^ MulAlpha[s5 >> 24])
                ^ ((s8 >> 8) ^ DivAlpha[s8 & 0xFF]) ^ s4;
            f3 = (s4 + r1) ^ r2;

            /*
             * Apply the third S-box (number 2) on (f3, f2, f1, f0).
             */
            f4 = f0;
            f0 &= f2;
            f0 ^= f3;
            f2 ^= f1;
            f2 ^= f0;
            f3 |= f4;
            f3 ^= f1;
            f4 ^= f2;
            f1 = f3;
            f3 |= f4;
            f3 ^= f0;
            f0 &= f1;
            f4 ^= f0;
            f1 ^= f3;
            f1 ^= f4;
            f4 = ~f4;

            /*
             * S-box result is in (f2, f3, f1, f4).
             */
            outputUintPtr[12] = (f2 ^ v0) ^ inputUintPtr[12];
            outputUintPtr[13] = (f3 ^ v1) ^ inputUintPtr[13];
            outputUintPtr[14] = (f1 ^ v2) ^ inputUintPtr[14];
            outputUintPtr[15] = (f4 ^ v3) ^ inputUintPtr[15];

            tt = r1;
            r1 = r2 + (s7 ^ ((r1 & 0x01) != 0 ? s4 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v0 = s6;
            s6 = ((s6 << 8) ^ MulAlpha[s6 >> 24])
                ^ ((s9 >> 8) ^ DivAlpha[s9 & 0xFF]) ^ s5;
            f0 = (s5 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v1 = s7;
            s7 = ((s7 << 8) ^ MulAlpha[s7 >> 24])
                ^ ((s0 >> 8) ^ DivAlpha[s0 & 0xFF]) ^ s6;
            f1 = (s6 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s9 ^ ((r1 & 0x01) != 0 ? s6 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v2 = s8;
            s8 = ((s8 << 8) ^ MulAlpha[s8 >> 24])
                ^ ((s1 >> 8) ^ DivAlpha[s1 & 0xFF]) ^ s7;
            f2 = (s7 + r1) ^ r2;

            tt = r1;
            r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
            r2 = (tt * 0x54655307).RotateLeft_NoChecks(7);
            v3 = s9;
            s9 = ((s9 << 8) ^ MulAlpha[s9 >> 24])
                ^ ((s2 >> 8) ^ DivAlpha[s2 & 0xFF]) ^ s8;
            f3 = (s8 + r1) ^ r2;

            /*
             * Apply the third S-box (number 2) on (f3, f2, f1, f0).
             */
            f4 = f0;
            f0 &= f2;
            f0 ^= f3;
            f2 ^= f1;
            f2 ^= f0;
            f3 |= f4;
            f3 ^= f1;
            f4 ^= f2;
            f1 = f3;
            f3 |= f4;
            f3 ^= f0;
            f0 &= f1;
            f4 ^= f0;
            f1 ^= f3;
            f1 ^= f4;
            f4 = ~f4;

            /*
             * S-box result is in (f2, f3, f1, f4).
             */
            outputUintPtr[16] = (f2 ^ v0) ^ inputUintPtr[16];
            outputUintPtr[17] = (f3 ^ v1) ^ inputUintPtr[17];
            outputUintPtr[18] = (f1 ^ v2) ^ inputUintPtr[18];
            outputUintPtr[19] = (f4 ^ v3) ^ inputUintPtr[19];

            lfsr0 = s0;
            lfsr1 = s1;
            lfsr2 = s2;
            lfsr3 = s3;
            lfsr4 = s4;
            lfsr5 = s5;
            lfsr6 = s6;
            lfsr7 = s7;
            lfsr8 = s8;
            lfsr9 = s9;
            fsmR1 = r1;
            fsmR2 = r2;
        }
#endif

        /// <summary>
        /// Initialise the engine state with key material.
        /// </summary>
        private void KeySetup (byte[] key) {
			if (key.Length == 32) {
				Key = key;
			} else {
                Key = new byte[32];
                Array.Copy(key, 0, Key, 0, key.Length);
                Key[key.Length] = 0x01;
                for (int j = key.Length + 1; j < Key.Length; j++) {
                    Key[j] = 0x00;
				}
			}

			uint w0, w1, w2, w3, w4, w5, w6, w7;
            uint r0, r1, r2, r3, r4, tt;
            uint i = 0;

            w0 = Key.LittleEndianToUInt32(0);
            w1 = Key.LittleEndianToUInt32(4);
            w2 = Key.LittleEndianToUInt32(8);
            w3 = Key.LittleEndianToUInt32(12);
            w4 = Key.LittleEndianToUInt32(16);
            w5 = Key.LittleEndianToUInt32(20);
            w6 = Key.LittleEndianToUInt32(24);
            w7 = Key.LittleEndianToUInt32(28);

            tt = (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (0)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt = (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (0 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt = (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (0 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt = (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (0 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r4 = r0;
            r0 |= r3;
            r3 ^= r1;
            r1 &= r4;
            r4 ^= r2;
            r2 ^= r3;
            r3 &= r0;
            r4 |= r1;
            r3 ^= r4;
            r0 ^= r1;
            r4 &= r0;
            r1 ^= r3;
            r4 ^= r2;
            r1 |= r0;
            r1 ^= r2;
            r0 ^= r3;
            r2 = r1;
            r1 |= r3;
            r1 ^= r0;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r4;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (4)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (4 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (4 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (4 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r4 = r0;
            r0 &= r2;
            r0 ^= r3;
            r2 ^= r1;
            r2 ^= r0;
            r3 |= r4;
            r3 ^= r1;
            r4 ^= r2;
            r1 = r3;
            r3 |= r4;
            r3 ^= r0;
            r0 &= r1;
            r4 ^= r0;
            r1 ^= r3;
            r1 ^= r4;
            r4 = ~r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (8)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (8 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (8 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (8 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r0 = ~r0;
            r2 = ~r2;
            r4 = r0;
            r0 &= r1;
            r2 ^= r0;
            r0 |= r3;
            r3 ^= r2;
            r1 ^= r0;
            r0 ^= r4;
            r4 |= r1;
            r1 ^= r3;
            r2 |= r0;
            r2 &= r4;
            r0 ^= r1;
            r1 &= r2;
            r1 ^= r0;
            r0 &= r2;
            r0 ^= r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (12)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (12 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (12 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (12 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r3 ^= r0;
            r4 = r1;
            r1 &= r3;
            r4 ^= r2;
            r1 ^= r0;
            r0 |= r3;
            r0 ^= r4;
            r4 ^= r3;
            r3 ^= r2;
            r2 |= r1;
            r2 ^= r4;
            r4 = ~r4;
            r4 |= r1;
            r1 ^= r3;
            r1 ^= r4;
            r3 |= r0;
            r1 ^= r3;
            r4 ^= r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r0;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (16)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (16 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (16 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (16 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r4 = r1;
            r1 |= r2;
            r1 ^= r3;
            r4 ^= r2;
            r2 ^= r1;
            r3 |= r4;
            r3 &= r0;
            r4 ^= r2;
            r3 ^= r1;
            r1 |= r4;
            r1 ^= r0;
            r0 |= r4;
            r0 ^= r2;
            r1 ^= r4;
            r2 ^= r1;
            r1 &= r0;
            r1 ^= r4;
            r2 = ~r2;
            r2 |= r0;
            r4 ^= r2;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r0;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (20)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (20 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (20 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (20 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r2 = ~r2;
            r4 = r3;
            r3 &= r0;
            r0 ^= r4;
            r3 ^= r2;
            r2 |= r4;
            r1 ^= r3;
            r2 ^= r0;
            r0 |= r1;
            r2 ^= r1;
            r4 ^= r0;
            r0 |= r3;
            r0 ^= r2;
            r4 ^= r3;
            r4 ^= r0;
            r3 = ~r3;
            r2 &= r4;
            r2 ^= r3;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r2;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (24)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (24 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (24 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (24 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r0 ^= r1;
            r1 ^= r3;
            r3 = ~r3;
            r4 = r1;
            r1 &= r0;
            r2 ^= r3;
            r1 ^= r2;
            r2 |= r4;
            r4 ^= r3;
            r3 &= r1;
            r3 ^= r0;
            r4 ^= r1;
            r4 ^= r2;
            r2 ^= r0;
            r0 &= r3;
            r2 = ~r2;
            r0 ^= r4;
            r4 |= r3;
            r2 ^= r4;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r2;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (28)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (28 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (28 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (28 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r1 ^= r3;
            r3 = ~r3;
            r2 ^= r3;
            r3 ^= r0;
            r4 = r1;
            r1 &= r3;
            r1 ^= r2;
            r4 ^= r3;
            r0 ^= r4;
            r2 &= r4;
            r2 ^= r0;
            r0 &= r1;
            r3 ^= r0;
            r4 |= r1;
            r4 ^= r0;
            r0 |= r3;
            r0 ^= r2;
            r2 &= r3;
            r0 = ~r0;
            r4 ^= r2;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r3;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (32)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (32 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (32 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (32 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r4 = r0;
            r0 |= r3;
            r3 ^= r1;
            r1 &= r4;
            r4 ^= r2;
            r2 ^= r3;
            r3 &= r0;
            r4 |= r1;
            r3 ^= r4;
            r0 ^= r1;
            r4 &= r0;
            r1 ^= r3;
            r4 ^= r2;
            r1 |= r0;
            r1 ^= r2;
            r0 ^= r3;
            r2 = r1;
            r1 |= r3;
            r1 ^= r0;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r4;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (36)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (36 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (36 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (36 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r4 = r0;
            r0 &= r2;
            r0 ^= r3;
            r2 ^= r1;
            r2 ^= r0;
            r3 |= r4;
            r3 ^= r1;
            r4 ^= r2;
            r1 = r3;
            r3 |= r4;
            r3 ^= r0;
            r0 &= r1;
            r4 ^= r0;
            r1 ^= r3;
            r1 ^= r4;
            r4 = ~r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (40)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (40 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (40 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (40 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r0 = ~r0;
            r2 = ~r2;
            r4 = r0;
            r0 &= r1;
            r2 ^= r0;
            r0 |= r3;
            r3 ^= r2;
            r1 ^= r0;
            r0 ^= r4;
            r4 |= r1;
            r1 ^= r3;
            r2 |= r0;
            r2 &= r4;
            r0 ^= r1;
            r1 &= r2;
            r1 ^= r0;
            r0 &= r2;
            r0 ^= r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (44)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (44 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (44 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (44 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r3 ^= r0;
            r4 = r1;
            r1 &= r3;
            r4 ^= r2;
            r1 ^= r0;
            r0 |= r3;
            r0 ^= r4;
            r4 ^= r3;
            r3 ^= r2;
            r2 |= r1;
            r2 ^= r4;
            r4 = ~r4;
            r4 |= r1;
            r1 ^= r3;
            r1 ^= r4;
            r3 |= r0;
            r1 ^= r3;
            r4 ^= r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r0;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (48)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (48 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (48 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (48 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r4 = r1;
            r1 |= r2;
            r1 ^= r3;
            r4 ^= r2;
            r2 ^= r1;
            r3 |= r4;
            r3 &= r0;
            r4 ^= r2;
            r3 ^= r1;
            r1 |= r4;
            r1 ^= r0;
            r0 |= r4;
            r0 ^= r2;
            r1 ^= r4;
            r2 ^= r1;
            r1 &= r0;
            r1 ^= r4;
            r2 = ~r2;
            r2 |= r0;
            r4 ^= r2;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r0;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (52)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (52 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (52 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (52 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r2 = ~r2;
            r4 = r3;
            r3 &= r0;
            r0 ^= r4;
            r3 ^= r2;
            r2 |= r4;
            r1 ^= r3;
            r2 ^= r0;
            r0 |= r1;
            r2 ^= r1;
            r4 ^= r0;
            r0 |= r3;
            r0 ^= r2;
            r4 ^= r3;
            r4 ^= r0;
            r3 = ~r3;
            r2 &= r4;
            r2 ^= r3;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r2;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (56)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (56 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (56 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (56 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r0 ^= r1;
            r1 ^= r3;
            r3 = ~r3;
            r4 = r1;
            r1 &= r0;
            r2 ^= r3;
            r1 ^= r2;
            r2 |= r4;
            r4 ^= r3;
            r3 &= r1;
            r3 ^= r0;
            r4 ^= r1;
            r4 ^= r2;
            r2 ^= r0;
            r0 &= r3;
            r2 = ~r2;
            r0 ^= r4;
            r4 |= r3;
            r2 ^= r4;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r2;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (60)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (60 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (60 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (60 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r1 ^= r3;
            r3 = ~r3;
            r2 ^= r3;
            r3 ^= r0;
            r4 = r1;
            r1 &= r3;
            r1 ^= r2;
            r4 ^= r3;
            r0 ^= r4;
            r2 &= r4;
            r2 ^= r0;
            r0 &= r1;
            r3 ^= r0;
            r4 |= r1;
            r4 ^= r0;
            r0 |= r3;
            r0 ^= r2;
            r2 &= r3;
            r0 = ~r0;
            r4 ^= r2;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r3;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (64)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (64 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (64 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (64 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r4 = r0;
            r0 |= r3;
            r3 ^= r1;
            r1 &= r4;
            r4 ^= r2;
            r2 ^= r3;
            r3 &= r0;
            r4 |= r1;
            r3 ^= r4;
            r0 ^= r1;
            r4 &= r0;
            r1 ^= r3;
            r4 ^= r2;
            r1 |= r0;
            r1 ^= r2;
            r0 ^= r3;
            r2 = r1;
            r1 |= r3;
            r1 ^= r0;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r4;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (68)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (68 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (68 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (68 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r4 = r0;
            r0 &= r2;
            r0 ^= r3;
            r2 ^= r1;
            r2 ^= r0;
            r3 |= r4;
            r3 ^= r1;
            r4 ^= r2;
            r1 = r3;
            r3 |= r4;
            r3 ^= r0;
            r0 &= r1;
            r4 ^= r0;
            r1 ^= r3;
            r1 ^= r4;
            r4 = ~r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (72)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (72 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (72 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (72 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r0 = ~r0;
            r2 = ~r2;
            r4 = r0;
            r0 &= r1;
            r2 ^= r0;
            r0 |= r3;
            r3 ^= r2;
            r1 ^= r0;
            r0 ^= r4;
            r4 |= r1;
            r1 ^= r3;
            r2 |= r0;
            r2 &= r4;
            r0 ^= r1;
            r1 &= r2;
            r1 ^= r0;
            r0 &= r2;
            r0 ^= r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (76)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (76 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (76 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (76 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r3 ^= r0;
            r4 = r1;
            r1 &= r3;
            r4 ^= r2;
            r1 ^= r0;
            r0 |= r3;
            r0 ^= r4;
            r4 ^= r3;
            r3 ^= r2;
            r2 |= r1;
            r2 ^= r4;
            r4 = ~r4;
            r4 |= r1;
            r1 ^= r3;
            r1 ^= r4;
            r3 |= r0;
            r1 ^= r3;
            r4 ^= r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r0;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (80)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (80 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (80 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (80 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r4 = r1;
            r1 |= r2;
            r1 ^= r3;
            r4 ^= r2;
            r2 ^= r1;
            r3 |= r4;
            r3 &= r0;
            r4 ^= r2;
            r3 ^= r1;
            r1 |= r4;
            r1 ^= r0;
            r0 |= r4;
            r0 ^= r2;
            r1 ^= r4;
            r2 ^= r1;
            r1 &= r0;
            r1 ^= r4;
            r2 = ~r2;
            r2 |= r0;
            r4 ^= r2;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r0;
			tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (84)));
            w4 = tt.RotateLeft_NoChecks(11);
			tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (84 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
			tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (84 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
			tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (84 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r2 = ~r2;
            r4 = r3;
            r3 &= r0;
            r0 ^= r4;
            r3 ^= r2;
            r2 |= r4;
            r1 ^= r3;
            r2 ^= r0;
            r0 |= r1;
            r2 ^= r1;
            r4 ^= r0;
            r0 |= r3;
            r0 ^= r2;
            r4 ^= r3;
            r4 ^= r0;
            r3 = ~r3;
            r2 &= r4;
            r2 ^= r3;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r2;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (88)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (88 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (88 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (88 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r0 ^= r1;
            r1 ^= r3;
            r3 = ~r3;
            r4 = r1;
            r1 &= r0;
            r2 ^= r3;
            r1 ^= r2;
            r2 |= r4;
            r4 ^= r3;
            r3 &= r1;
            r3 ^= r0;
            r4 ^= r1;
            r4 ^= r2;
            r2 ^= r0;
            r0 &= r3;
            r2 = ~r2;
            r0 ^= r4;
            r4 |= r3;
            r2 ^= r4;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r2;
            tt =  (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (92)));
            w4 = tt.RotateLeft_NoChecks(11);
            tt =  (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (92 + 1)));
            w5 = tt.RotateLeft_NoChecks(11);
            tt =  (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (92 + 2)));
            w6 = tt.RotateLeft_NoChecks(11);
            tt =  (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (92 + 3)));
            w7 = tt.RotateLeft_NoChecks(11);
            r0 = w4;
            r1 = w5;
            r2 = w6;
            r3 = w7;
            r1 ^= r3;
            r3 = ~r3;
            r2 ^= r3;
            r3 ^= r0;
            r4 = r1;
            r1 &= r3;
            r1 ^= r2;
            r4 ^= r3;
            r0 ^= r4;
            r2 &= r4;
            r2 ^= r0;
            r0 &= r1;
            r3 ^= r0;
            r4 |= r1;
            r4 ^= r0;
            r0 |= r3;
            r0 ^= r2;
            r2 &= r3;
            r0 = ~r0;
            r4 ^= r2;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r4;
            _serpent24SubKeys[i++] = r0;
            _serpent24SubKeys[i++] = r3;
            tt =  (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (96)));
            w0 = tt.RotateLeft_NoChecks(11);
            tt =  (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (96 + 1)));
            w1 = tt.RotateLeft_NoChecks(11);
            tt =  (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (96 + 2)));
            w2 = tt.RotateLeft_NoChecks(11);
            tt =  (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (96 + 3)));
            w3 = tt.RotateLeft_NoChecks(11);
            r0 = w0;
            r1 = w1;
            r2 = w2;
            r3 = w3;
            r4 = r0;
            r0 |= r3;
            r3 ^= r1;
            r1 &= r4;
            r4 ^= r2;
            r2 ^= r3;
            r3 &= r0;
            r4 |= r1;
            r3 ^= r4;
            r0 ^= r1;
            r4 &= r0;
            r1 ^= r3;
            r4 ^= r2;
            r1 |= r0;
            r1 ^= r2;
            r0 ^= r3;
            r2 = r1;
            r1 |= r3;
            r1 ^= r0;
            _serpent24SubKeys[i++] = r1;
            _serpent24SubKeys[i++] = r2;
            _serpent24SubKeys[i++] = r3;
            _serpent24SubKeys[i++] = r4;
        }

        /// <summary>
        /// Initialise the engine state with initialisation vector material.
        /// </summary>
        private void IVSetup (byte[] iv) {
			if (iv == null)
				iv = new byte[0];
			if (iv.Length == 16) {
                Nonce = iv;
			} else {
                Nonce = new byte[16];
                Array.Copy(iv, 0, Nonce, 0, iv.Length);
                for (int i = iv.Length; i < Nonce.Length; i++)
                    Nonce[i] = 0x00;
			}

            uint r0, r1, r2, r3, r4;

            r0 = Nonce.LittleEndianToUInt32(0);
            r1 = Nonce.LittleEndianToUInt32(4);
            r2 = Nonce.LittleEndianToUInt32(8);
            r3 = Nonce.LittleEndianToUInt32(12);

            r0 ^= _serpent24SubKeys[0];
            r1 ^= _serpent24SubKeys[0 + 1];
            r2 ^= _serpent24SubKeys[0 + 2];
            r3 ^= _serpent24SubKeys[0 + 3];
            r3 ^= r0;
            r4 = r1;
            r1 &= r3;
            r4 ^= r2;
            r1 ^= r0;
            r0 |= r3;
            r0 ^= r4;
            r4 ^= r3;
            r3 ^= r2;
            r2 |= r1;
            r2 ^= r4;
            r4 = ~r4;
            r4 |= r1;
            r1 ^= r3;
            r1 ^= r4;
            r3 |= r0;
            r1 ^= r3;
            r4 ^= r3;
            r1 = r1.RotateLeft_NoChecks(13);
            r2 = r2.RotateLeft_NoChecks(3);
            r4 = r4 ^ r1 ^ r2;
            r0 = r0 ^ r2 ^ (r1 << 3);
            r4 = r4.RotateLeft_NoChecks(1);
            r0 = r0.RotateLeft_NoChecks(7);
            r1 = r1 ^ r4 ^ r0;
            r2 = r2 ^ r0 ^ (r4 << 7);
            r1 = r1.RotateLeft_NoChecks(5);
            r2 = r2.RotateLeft_NoChecks(22);
            r1 ^= _serpent24SubKeys[4];
            r4 ^= _serpent24SubKeys[4 + 1];
            r2 ^= _serpent24SubKeys[4 + 2];
            r0 ^= _serpent24SubKeys[4 + 3];
            r1 = ~r1;
            r2 = ~r2;
            r3 = r1;
            r1 &= r4;
            r2 ^= r1;
            r1 |= r0;
            r0 ^= r2;
            r4 ^= r1;
            r1 ^= r3;
            r3 |= r4;
            r4 ^= r0;
            r2 |= r1;
            r2 &= r3;
            r1 ^= r4;
            r4 &= r2;
            r4 ^= r1;
            r1 &= r2;
            r1 ^= r3;
            r2 = r2.RotateLeft_NoChecks(13);
            r0 = r0.RotateLeft_NoChecks(3);
            r1 = r1 ^ r2 ^ r0;
            r4 = r4 ^ r0 ^ (r2 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r4 = r4.RotateLeft_NoChecks(7);
            r2 = r2 ^ r1 ^ r4;
            r0 = r0 ^ r4 ^ (r1 << 7);
            r2 = r2.RotateLeft_NoChecks(5);
            r0 = r0.RotateLeft_NoChecks(22);
            r2 ^= _serpent24SubKeys[8];
            r1 ^= _serpent24SubKeys[8 + 1];
            r0 ^= _serpent24SubKeys[8 + 2];
            r4 ^= _serpent24SubKeys[8 + 3];
            r3 = r2;
            r2 &= r0;
            r2 ^= r4;
            r0 ^= r1;
            r0 ^= r2;
            r4 |= r3;
            r4 ^= r1;
            r3 ^= r0;
            r1 = r4;
            r4 |= r3;
            r4 ^= r2;
            r2 &= r1;
            r3 ^= r2;
            r1 ^= r4;
            r1 ^= r3;
            r3 = ~r3;
            r0 = r0.RotateLeft_NoChecks(13);
            r1 = r1.RotateLeft_NoChecks(3);
            r4 = r4 ^ r0 ^ r1;
            r3 = r3 ^ r1 ^ (r0 << 3);
            r4 = r4.RotateLeft_NoChecks(1);
            r3 = r3.RotateLeft_NoChecks(7);
            r0 = r0 ^ r4 ^ r3;
            r1 = r1 ^ r3 ^ (r4 << 7);
            r0 = r0.RotateLeft_NoChecks(5);
            r1 = r1.RotateLeft_NoChecks(22);
            r0 ^= _serpent24SubKeys[12];
            r4 ^= _serpent24SubKeys[12 + 1];
            r1 ^= _serpent24SubKeys[12 + 2];
            r3 ^= _serpent24SubKeys[12 + 3];
            r2 = r0;
            r0 |= r3;
            r3 ^= r4;
            r4 &= r2;
            r2 ^= r1;
            r1 ^= r3;
            r3 &= r0;
            r2 |= r4;
            r3 ^= r2;
            r0 ^= r4;
            r2 &= r0;
            r4 ^= r3;
            r2 ^= r1;
            r4 |= r0;
            r4 ^= r1;
            r0 ^= r3;
            r1 = r4;
            r4 |= r3;
            r4 ^= r0;
            r4 = r4.RotateLeft_NoChecks(13);
            r3 = r3.RotateLeft_NoChecks(3);
            r1 = r1 ^ r4 ^ r3;
            r2 = r2 ^ r3 ^ (r4 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r2 = r2.RotateLeft_NoChecks(7);
            r4 = r4 ^ r1 ^ r2;
            r3 = r3 ^ r2 ^ (r1 << 7);
            r4 = r4.RotateLeft_NoChecks(5);
            r3 = r3.RotateLeft_NoChecks(22);
            r4 ^= _serpent24SubKeys[16];
            r1 ^= _serpent24SubKeys[16 + 1];
            r3 ^= _serpent24SubKeys[16 + 2];
            r2 ^= _serpent24SubKeys[16 + 3];
            r1 ^= r2;
            r2 = ~r2;
            r3 ^= r2;
            r2 ^= r4;
            r0 = r1;
            r1 &= r2;
            r1 ^= r3;
            r0 ^= r2;
            r4 ^= r0;
            r3 &= r0;
            r3 ^= r4;
            r4 &= r1;
            r2 ^= r4;
            r0 |= r1;
            r0 ^= r4;
            r4 |= r2;
            r4 ^= r3;
            r3 &= r2;
            r4 = ~r4;
            r0 ^= r3;
            r1 = r1.RotateLeft_NoChecks(13);
            r4 = r4.RotateLeft_NoChecks(3);
            r0 = r0 ^ r1 ^ r4;
            r2 = r2 ^ r4 ^ (r1 << 3);
            r0 = r0.RotateLeft_NoChecks(1);
            r2 = r2.RotateLeft_NoChecks(7);
            r1 = r1 ^ r0 ^ r2;
            r4 = r4 ^ r2 ^ (r0 << 7);
            r1 = r1.RotateLeft_NoChecks(5);
            r4 = r4.RotateLeft_NoChecks(22);
            r1 ^= _serpent24SubKeys[20];
            r0 ^= _serpent24SubKeys[20 + 1];
            r4 ^= _serpent24SubKeys[20 + 2];
            r2 ^= _serpent24SubKeys[20 + 3];
            r1 ^= r0;
            r0 ^= r2;
            r2 = ~r2;
            r3 = r0;
            r0 &= r1;
            r4 ^= r2;
            r0 ^= r4;
            r4 |= r3;
            r3 ^= r2;
            r2 &= r0;
            r2 ^= r1;
            r3 ^= r0;
            r3 ^= r4;
            r4 ^= r1;
            r1 &= r2;
            r4 = ~r4;
            r1 ^= r3;
            r3 |= r2;
            r4 ^= r3;
            r0 = r0.RotateLeft_NoChecks(13);
            r1 = r1.RotateLeft_NoChecks(3);
            r2 = r2 ^ r0 ^ r1;
            r4 = r4 ^ r1 ^ (r0 << 3);
            r2 = r2.RotateLeft_NoChecks(1);
            r4 = r4.RotateLeft_NoChecks(7);
            r0 = r0 ^ r2 ^ r4;
            r1 = r1 ^ r4 ^ (r2 << 7);
            r0 = r0.RotateLeft_NoChecks(5);
            r1 = r1.RotateLeft_NoChecks(22);
            r0 ^= _serpent24SubKeys[24];
            r2 ^= _serpent24SubKeys[24 + 1];
            r1 ^= _serpent24SubKeys[24 + 2];
            r4 ^= _serpent24SubKeys[24 + 3];
            r1 = ~r1;
            r3 = r4;
            r4 &= r0;
            r0 ^= r3;
            r4 ^= r1;
            r1 |= r3;
            r2 ^= r4;
            r1 ^= r0;
            r0 |= r2;
            r1 ^= r2;
            r3 ^= r0;
            r0 |= r4;
            r0 ^= r1;
            r3 ^= r4;
            r3 ^= r0;
            r4 = ~r4;
            r1 &= r3;
            r1 ^= r4;
            r0 = r0.RotateLeft_NoChecks(13);
            r3 = r3.RotateLeft_NoChecks(3);
            r2 = r2 ^ r0 ^ r3;
            r1 = r1 ^ r3 ^ (r0 << 3);
            r2 = r2.RotateLeft_NoChecks(1);
            r1 = r1.RotateLeft_NoChecks(7);
            r0 = r0 ^ r2 ^ r1;
            r3 = r3 ^ r1 ^ (r2 << 7);
            r0 = r0.RotateLeft_NoChecks(5);
            r3 = r3.RotateLeft_NoChecks(22);
            r0 ^= _serpent24SubKeys[28];
            r2 ^= _serpent24SubKeys[28 + 1];
            r3 ^= _serpent24SubKeys[28 + 2];
            r1 ^= _serpent24SubKeys[28 + 3];
            r4 = r2;
            r2 |= r3;
            r2 ^= r1;
            r4 ^= r3;
            r3 ^= r2;
            r1 |= r4;
            r1 &= r0;
            r4 ^= r3;
            r1 ^= r2;
            r2 |= r4;
            r2 ^= r0;
            r0 |= r4;
            r0 ^= r3;
            r2 ^= r4;
            r3 ^= r2;
            r2 &= r0;
            r2 ^= r4;
            r3 = ~r3;
            r3 |= r0;
            r4 ^= r3;
            r4 = r4.RotateLeft_NoChecks(13);
            r2 = r2.RotateLeft_NoChecks(3);
            r1 = r1 ^ r4 ^ r2;
            r0 = r0 ^ r2 ^ (r4 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r0 = r0.RotateLeft_NoChecks(7);
            r4 = r4 ^ r1 ^ r0;
            r2 = r2 ^ r0 ^ (r1 << 7);
            r4 = r4.RotateLeft_NoChecks(5);
            r2 = r2.RotateLeft_NoChecks(22);
            r4 ^= _serpent24SubKeys[32];
            r1 ^= _serpent24SubKeys[32 + 1];
            r2 ^= _serpent24SubKeys[32 + 2];
            r0 ^= _serpent24SubKeys[32 + 3];
            r0 ^= r4;
            r3 = r1;
            r1 &= r0;
            r3 ^= r2;
            r1 ^= r4;
            r4 |= r0;
            r4 ^= r3;
            r3 ^= r0;
            r0 ^= r2;
            r2 |= r1;
            r2 ^= r3;
            r3 = ~r3;
            r3 |= r1;
            r1 ^= r0;
            r1 ^= r3;
            r0 |= r4;
            r1 ^= r0;
            r3 ^= r0;
            r1 = r1.RotateLeft_NoChecks(13);
            r2 = r2.RotateLeft_NoChecks(3);
            r3 = r3 ^ r1 ^ r2;
            r4 = r4 ^ r2 ^ (r1 << 3);
            r3 = r3.RotateLeft_NoChecks(1);
            r4 = r4.RotateLeft_NoChecks(7);
            r1 = r1 ^ r3 ^ r4;
            r2 = r2 ^ r4 ^ (r3 << 7);
            r1 = r1.RotateLeft_NoChecks(5);
            r2 = r2.RotateLeft_NoChecks(22);
            r1 ^= _serpent24SubKeys[36];
            r3 ^= _serpent24SubKeys[36 + 1];
            r2 ^= _serpent24SubKeys[36 + 2];
            r4 ^= _serpent24SubKeys[36 + 3];
            r1 = ~r1;
            r2 = ~r2;
            r0 = r1;
            r1 &= r3;
            r2 ^= r1;
            r1 |= r4;
            r4 ^= r2;
            r3 ^= r1;
            r1 ^= r0;
            r0 |= r3;
            r3 ^= r4;
            r2 |= r1;
            r2 &= r0;
            r1 ^= r3;
            r3 &= r2;
            r3 ^= r1;
            r1 &= r2;
            r1 ^= r0;
            r2 = r2.RotateLeft_NoChecks(13);
            r4 = r4.RotateLeft_NoChecks(3);
            r1 = r1 ^ r2 ^ r4;
            r3 = r3 ^ r4 ^ (r2 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r3 = r3.RotateLeft_NoChecks(7);
            r2 = r2 ^ r1 ^ r3;
            r4 = r4 ^ r3 ^ (r1 << 7);
            r2 = r2.RotateLeft_NoChecks(5);
            r4 = r4.RotateLeft_NoChecks(22);
            r2 ^= _serpent24SubKeys[40];
            r1 ^= _serpent24SubKeys[40 + 1];
            r4 ^= _serpent24SubKeys[40 + 2];
            r3 ^= _serpent24SubKeys[40 + 3];
            r0 = r2;
            r2 &= r4;
            r2 ^= r3;
            r4 ^= r1;
            r4 ^= r2;
            r3 |= r0;
            r3 ^= r1;
            r0 ^= r4;
            r1 = r3;
            r3 |= r0;
            r3 ^= r2;
            r2 &= r1;
            r0 ^= r2;
            r1 ^= r3;
            r1 ^= r0;
            r0 = ~r0;
            r4 = r4.RotateLeft_NoChecks(13);
            r1 = r1.RotateLeft_NoChecks(3);
            r3 = r3 ^ r4 ^ r1;
            r0 = r0 ^ r1 ^ (r4 << 3);
            r3 = r3.RotateLeft_NoChecks(1);
            r0 = r0.RotateLeft_NoChecks(7);
            r4 = r4 ^ r3 ^ r0;
            r1 = r1 ^ r0 ^ (r3 << 7);
            r4 = r4.RotateLeft_NoChecks(5);
            r1 = r1.RotateLeft_NoChecks(22);
            r4 ^= _serpent24SubKeys[44];
            r3 ^= _serpent24SubKeys[44 + 1];
            r1 ^= _serpent24SubKeys[44 + 2];
            r0 ^= _serpent24SubKeys[44 + 3];
            r2 = r4;
            r4 |= r0;
            r0 ^= r3;
            r3 &= r2;
            r2 ^= r1;
            r1 ^= r0;
            r0 &= r4;
            r2 |= r3;
            r0 ^= r2;
            r4 ^= r3;
            r2 &= r4;
            r3 ^= r0;
            r2 ^= r1;
            r3 |= r4;
            r3 ^= r1;
            r4 ^= r0;
            r1 = r3;
            r3 |= r0;
            r3 ^= r4;
            r3 = r3.RotateLeft_NoChecks(13);
            r0 = r0.RotateLeft_NoChecks(3);
            r1 = r1 ^ r3 ^ r0;
            r2 = r2 ^ r0 ^ (r3 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r2 = r2.RotateLeft_NoChecks(7);
            r3 = r3 ^ r1 ^ r2;
            r0 = r0 ^ r2 ^ (r1 << 7);
            r3 = r3.RotateLeft_NoChecks(5);
            r0 = r0.RotateLeft_NoChecks(22);
            lfsr9 = r3;
            lfsr8 = r1;
            lfsr7 = r0;
            lfsr6 = r2;
            r3 ^= _serpent24SubKeys[48];
            r1 ^= _serpent24SubKeys[48 + 1];
            r0 ^= _serpent24SubKeys[48 + 2];
            r2 ^= _serpent24SubKeys[48 + 3];
            r1 ^= r2;
            r2 = ~r2;
            r0 ^= r2;
            r2 ^= r3;
            r4 = r1;
            r1 &= r2;
            r1 ^= r0;
            r4 ^= r2;
            r3 ^= r4;
            r0 &= r4;
            r0 ^= r3;
            r3 &= r1;
            r2 ^= r3;
            r4 |= r1;
            r4 ^= r3;
            r3 |= r2;
            r3 ^= r0;
            r0 &= r2;
            r3 = ~r3;
            r4 ^= r0;
            r1 = r1.RotateLeft_NoChecks(13);
            r3 = r3.RotateLeft_NoChecks(3);
            r4 = r4 ^ r1 ^ r3;
            r2 = r2 ^ r3 ^ (r1 << 3);
            r4 = r4.RotateLeft_NoChecks(1);
            r2 = r2.RotateLeft_NoChecks(7);
            r1 = r1 ^ r4 ^ r2;
            r3 = r3 ^ r2 ^ (r4 << 7);
            r1 = r1.RotateLeft_NoChecks(5);
            r3 = r3.RotateLeft_NoChecks(22);
            r1 ^= _serpent24SubKeys[52];
            r4 ^= _serpent24SubKeys[52 + 1];
            r3 ^= _serpent24SubKeys[52 + 2];
            r2 ^= _serpent24SubKeys[52 + 3];
            r1 ^= r4;
            r4 ^= r2;
            r2 = ~r2;
            r0 = r4;
            r4 &= r1;
            r3 ^= r2;
            r4 ^= r3;
            r3 |= r0;
            r0 ^= r2;
            r2 &= r4;
            r2 ^= r1;
            r0 ^= r4;
            r0 ^= r3;
            r3 ^= r1;
            r1 &= r2;
            r3 = ~r3;
            r1 ^= r0;
            r0 |= r2;
            r3 ^= r0;
            r4 = r4.RotateLeft_NoChecks(13);
            r1 = r1.RotateLeft_NoChecks(3);
            r2 = r2 ^ r4 ^ r1;
            r3 = r3 ^ r1 ^ (r4 << 3);
            r2 = r2.RotateLeft_NoChecks(1);
            r3 = r3.RotateLeft_NoChecks(7);
            r4 = r4 ^ r2 ^ r3;
            r1 = r1 ^ r3 ^ (r2 << 7);
            r4 = r4.RotateLeft_NoChecks(5);
            r1 = r1.RotateLeft_NoChecks(22);
            r4 ^= _serpent24SubKeys[56];
            r2 ^= _serpent24SubKeys[56 + 1];
            r1 ^= _serpent24SubKeys[56 + 2];
            r3 ^= _serpent24SubKeys[56 + 3];
            r1 = ~r1;
            r0 = r3;
            r3 &= r4;
            r4 ^= r0;
            r3 ^= r1;
            r1 |= r0;
            r2 ^= r3;
            r1 ^= r4;
            r4 |= r2;
            r1 ^= r2;
            r0 ^= r4;
            r4 |= r3;
            r4 ^= r1;
            r0 ^= r3;
            r0 ^= r4;
            r3 = ~r3;
            r1 &= r0;
            r1 ^= r3;
            r4 = r4.RotateLeft_NoChecks(13);
            r0 = r0.RotateLeft_NoChecks(3);
            r2 = r2 ^ r4 ^ r0;
            r1 = r1 ^ r0 ^ (r4 << 3);
            r2 = r2.RotateLeft_NoChecks(1);
            r1 = r1.RotateLeft_NoChecks(7);
            r4 = r4 ^ r2 ^ r1;
            r0 = r0 ^ r1 ^ (r2 << 7);
            r4 = r4.RotateLeft_NoChecks(5);
            r0 = r0.RotateLeft_NoChecks(22);
            r4 ^= _serpent24SubKeys[60];
            r2 ^= _serpent24SubKeys[60 + 1];
            r0 ^= _serpent24SubKeys[60 + 2];
            r1 ^= _serpent24SubKeys[60 + 3];
            r3 = r2;
            r2 |= r0;
            r2 ^= r1;
            r3 ^= r0;
            r0 ^= r2;
            r1 |= r3;
            r1 &= r4;
            r3 ^= r0;
            r1 ^= r2;
            r2 |= r3;
            r2 ^= r4;
            r4 |= r3;
            r4 ^= r0;
            r2 ^= r3;
            r0 ^= r2;
            r2 &= r4;
            r2 ^= r3;
            r0 = ~r0;
            r0 |= r4;
            r3 ^= r0;
            r3 = r3.RotateLeft_NoChecks(13);
            r2 = r2.RotateLeft_NoChecks(3);
            r1 = r1 ^ r3 ^ r2;
            r4 = r4 ^ r2 ^ (r3 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r4 = r4.RotateLeft_NoChecks(7);
            r3 = r3 ^ r1 ^ r4;
            r2 = r2 ^ r4 ^ (r1 << 7);
            r3 = r3.RotateLeft_NoChecks(5);
            r2 = r2.RotateLeft_NoChecks(22);
            r3 ^= _serpent24SubKeys[64];
            r1 ^= _serpent24SubKeys[64 + 1];
            r2 ^= _serpent24SubKeys[64 + 2];
            r4 ^= _serpent24SubKeys[64 + 3];
            r4 ^= r3;
            r0 = r1;
            r1 &= r4;
            r0 ^= r2;
            r1 ^= r3;
            r3 |= r4;
            r3 ^= r0;
            r0 ^= r4;
            r4 ^= r2;
            r2 |= r1;
            r2 ^= r0;
            r0 = ~r0;
            r0 |= r1;
            r1 ^= r4;
            r1 ^= r0;
            r4 |= r3;
            r1 ^= r4;
            r0 ^= r4;
            r1 = r1.RotateLeft_NoChecks(13);
            r2 = r2.RotateLeft_NoChecks(3);
            r0 = r0 ^ r1 ^ r2;
            r3 = r3 ^ r2 ^ (r1 << 3);
            r0 = r0.RotateLeft_NoChecks(1);
            r3 = r3.RotateLeft_NoChecks(7);
            r1 = r1 ^ r0 ^ r3;
            r2 = r2 ^ r3 ^ (r0 << 7);
            r1 = r1.RotateLeft_NoChecks(5);
            r2 = r2.RotateLeft_NoChecks(22);
            r1 ^= _serpent24SubKeys[68];
            r0 ^= _serpent24SubKeys[68 + 1];
            r2 ^= _serpent24SubKeys[68 + 2];
            r3 ^= _serpent24SubKeys[68 + 3];
            r1 = ~r1;
            r2 = ~r2;
            r4 = r1;
            r1 &= r0;
            r2 ^= r1;
            r1 |= r3;
            r3 ^= r2;
            r0 ^= r1;
            r1 ^= r4;
            r4 |= r0;
            r0 ^= r3;
            r2 |= r1;
            r2 &= r4;
            r1 ^= r0;
            r0 &= r2;
            r0 ^= r1;
            r1 &= r2;
            r1 ^= r4;
            r2 = r2.RotateLeft_NoChecks(13);
            r3 = r3.RotateLeft_NoChecks(3);
            r1 = r1 ^ r2 ^ r3;
            r0 = r0 ^ r3 ^ (r2 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r0 = r0.RotateLeft_NoChecks(7);
            r2 = r2 ^ r1 ^ r0;
            r3 = r3 ^ r0 ^ (r1 << 7);
            r2 = r2.RotateLeft_NoChecks(5);
            r3 = r3.RotateLeft_NoChecks(22);
            fsmR1 = r2;
            lfsr4 = r1;
            fsmR2 = r3;
            lfsr5 = r0;
            r2 ^= _serpent24SubKeys[72];
            r1 ^= _serpent24SubKeys[72 + 1];
            r3 ^= _serpent24SubKeys[72 + 2];
            r0 ^= _serpent24SubKeys[72 + 3];
            r4 = r2;
            r2 &= r3;
            r2 ^= r0;
            r3 ^= r1;
            r3 ^= r2;
            r0 |= r4;
            r0 ^= r1;
            r4 ^= r3;
            r1 = r0;
            r0 |= r4;
            r0 ^= r2;
            r2 &= r1;
            r4 ^= r2;
            r1 ^= r0;
            r1 ^= r4;
            r4 = ~r4;
            r3 = r3.RotateLeft_NoChecks(13);
            r1 = r1.RotateLeft_NoChecks(3);
            r0 = r0 ^ r3 ^ r1;
            r4 = r4 ^ r1 ^ (r3 << 3);
            r0 = r0.RotateLeft_NoChecks(1);
            r4 = r4.RotateLeft_NoChecks(7);
            r3 = r3 ^ r0 ^ r4;
            r1 = r1 ^ r4 ^ (r0 << 7);
            r3 = r3.RotateLeft_NoChecks(5);
            r1 = r1.RotateLeft_NoChecks(22);
            r3 ^= _serpent24SubKeys[76];
            r0 ^= _serpent24SubKeys[76 + 1];
            r1 ^= _serpent24SubKeys[76 + 2];
            r4 ^= _serpent24SubKeys[76 + 3];
            r2 = r3;
            r3 |= r4;
            r4 ^= r0;
            r0 &= r2;
            r2 ^= r1;
            r1 ^= r4;
            r4 &= r3;
            r2 |= r0;
            r4 ^= r2;
            r3 ^= r0;
            r2 &= r3;
            r0 ^= r4;
            r2 ^= r1;
            r0 |= r3;
            r0 ^= r1;
            r3 ^= r4;
            r1 = r0;
            r0 |= r4;
            r0 ^= r3;
            r0 = r0.RotateLeft_NoChecks(13);
            r4 = r4.RotateLeft_NoChecks(3);
            r1 = r1 ^ r0 ^ r4;
            r2 = r2 ^ r4 ^ (r0 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r2 = r2.RotateLeft_NoChecks(7);
            r0 = r0 ^ r1 ^ r2;
            r4 = r4 ^ r2 ^ (r1 << 7);
            r0 = r0.RotateLeft_NoChecks(5);
            r4 = r4.RotateLeft_NoChecks(22);
            r0 ^= _serpent24SubKeys[80];
            r1 ^= _serpent24SubKeys[80 + 1];
            r4 ^= _serpent24SubKeys[80 + 2];
            r2 ^= _serpent24SubKeys[80 + 3];
            r1 ^= r2;
            r2 = ~r2;
            r4 ^= r2;
            r2 ^= r0;
            r3 = r1;
            r1 &= r2;
            r1 ^= r4;
            r3 ^= r2;
            r0 ^= r3;
            r4 &= r3;
            r4 ^= r0;
            r0 &= r1;
            r2 ^= r0;
            r3 |= r1;
            r3 ^= r0;
            r0 |= r2;
            r0 ^= r4;
            r4 &= r2;
            r0 = ~r0;
            r3 ^= r4;
            r1 = r1.RotateLeft_NoChecks(13);
            r0 = r0.RotateLeft_NoChecks(3);
            r3 = r3 ^ r1 ^ r0;
            r2 = r2 ^ r0 ^ (r1 << 3);
            r3 = r3.RotateLeft_NoChecks(1);
            r2 = r2.RotateLeft_NoChecks(7);
            r1 = r1 ^ r3 ^ r2;
            r0 = r0 ^ r2 ^ (r3 << 7);
            r1 = r1.RotateLeft_NoChecks(5);
            r0 = r0.RotateLeft_NoChecks(22);
            r1 ^= _serpent24SubKeys[84];
            r3 ^= _serpent24SubKeys[84 + 1];
            r0 ^= _serpent24SubKeys[84 + 2];
            r2 ^= _serpent24SubKeys[84 + 3];
            r1 ^= r3;
            r3 ^= r2;
            r2 = ~r2;
            r4 = r3;
            r3 &= r1;
            r0 ^= r2;
            r3 ^= r0;
            r0 |= r4;
            r4 ^= r2;
            r2 &= r3;
            r2 ^= r1;
            r4 ^= r3;
            r4 ^= r0;
            r0 ^= r1;
            r1 &= r2;
            r0 = ~r0;
            r1 ^= r4;
            r4 |= r2;
            r0 ^= r4;
            r3 = r3.RotateLeft_NoChecks(13);
            r1 = r1.RotateLeft_NoChecks(3);
            r2 = r2 ^ r3 ^ r1;
            r0 = r0 ^ r1 ^ (r3 << 3);
            r2 = r2.RotateLeft_NoChecks(1);
            r0 = r0.RotateLeft_NoChecks(7);
            r3 = r3 ^ r2 ^ r0;
            r1 = r1 ^ r0 ^ (r2 << 7);
            r3 = r3.RotateLeft_NoChecks(5);
            r1 = r1.RotateLeft_NoChecks(22);
            r3 ^= _serpent24SubKeys[88];
            r2 ^= _serpent24SubKeys[88 + 1];
            r1 ^= _serpent24SubKeys[88 + 2];
            r0 ^= _serpent24SubKeys[88 + 3];
            r1 = ~r1;
            r4 = r0;
            r0 &= r3;
            r3 ^= r4;
            r0 ^= r1;
            r1 |= r4;
            r2 ^= r0;
            r1 ^= r3;
            r3 |= r2;
            r1 ^= r2;
            r4 ^= r3;
            r3 |= r0;
            r3 ^= r1;
            r4 ^= r0;
            r4 ^= r3;
            r0 = ~r0;
            r1 &= r4;
            r1 ^= r0;
            r3 = r3.RotateLeft_NoChecks(13);
            r4 = r4.RotateLeft_NoChecks(3);
            r2 = r2 ^ r3 ^ r4;
            r1 = r1 ^ r4 ^ (r3 << 3);
            r2 = r2.RotateLeft_NoChecks(1);
            r1 = r1.RotateLeft_NoChecks(7);
            r3 = r3 ^ r2 ^ r1;
            r4 = r4 ^ r1 ^ (r2 << 7);
            r3 = r3.RotateLeft_NoChecks(5);
            r4 = r4.RotateLeft_NoChecks(22);
            r3 ^= _serpent24SubKeys[92];
            r2 ^= _serpent24SubKeys[92 + 1];
            r4 ^= _serpent24SubKeys[92 + 2];
            r1 ^= _serpent24SubKeys[92 + 3];
            r0 = r2;
            r2 |= r4;
            r2 ^= r1;
            r0 ^= r4;
            r4 ^= r2;
            r1 |= r0;
            r1 &= r3;
            r0 ^= r4;
            r1 ^= r2;
            r2 |= r0;
            r2 ^= r3;
            r3 |= r0;
            r3 ^= r4;
            r2 ^= r0;
            r4 ^= r2;
            r2 &= r3;
            r2 ^= r0;
            r4 = ~r4;
            r4 |= r3;
            r0 ^= r4;
            r0 = r0.RotateLeft_NoChecks(13);
            r2 = r2.RotateLeft_NoChecks(3);
            r1 = r1 ^ r0 ^ r2;
            r3 = r3 ^ r2 ^ (r0 << 3);
            r1 = r1.RotateLeft_NoChecks(1);
            r3 = r3.RotateLeft_NoChecks(7);
            r0 = r0 ^ r1 ^ r3;
            r2 = r2 ^ r3 ^ (r1 << 7);
            r0 = r0.RotateLeft_NoChecks(5);
            r2 = r2.RotateLeft_NoChecks(22);
            r0 ^= _serpent24SubKeys[96];
            r1 ^= _serpent24SubKeys[96 + 1];
            r2 ^= _serpent24SubKeys[96 + 2];
            r3 ^= _serpent24SubKeys[96 + 3];
            lfsr3 = r0;
            lfsr2 = r1;
            lfsr1 = r2;
            lfsr0 = r3;
        }
        #endregion
    }
}
