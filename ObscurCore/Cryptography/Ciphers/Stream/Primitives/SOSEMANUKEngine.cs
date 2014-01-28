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
using ObscurCore.Cryptography.Entropy;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
    public sealed class SosemanukEngine : IStreamCipher, ICsprngCompatible
    {
		private const int BufferLen = 80;

		/// <summary>
		/// Internal buffer for partial blocks.
		/// </summary>
		private readonly byte[] _streamBuf = new byte[BufferLen];

		/// <summary>
		/// Points to the first stream byte which 
		/// has been computed but not output.
		/// </summary>
		private int _streamPtr = BufferLen;

        // Stores engine state
		private bool	        _initialised;
        private byte[]          _workingKey,
                                _workingIV;

        private uint lfsr0, lfsr1, lfsr2, lfsr3, lfsr4;
        private uint lfsr5, lfsr6, lfsr7, lfsr8, lfsr9;
        private uint fsmR1, fsmR2;
		// Subkeys for Serpent24: 100 32-bit words.
		private readonly uint[] _serpent24SubKeys = new uint[100];
        
		public void Init (bool encrypting, byte[] key, byte[] iv) {
			if (iv == null) 
				throw new ArgumentNullException("iv", "SOSEMANUK initialisation requires an IV.");
			else if (!iv.Length.IsBetween(4, 16))
				throw new ArgumentException("SOSEMANUK requires 4 to 16 bytes (32 to 128 bits) of IV.", "iv");

			if (key == null) 
				throw new ArgumentNullException("key", "SOSEMANUK initialisation requires a key.");
			else if (!key.Length.IsBetween(8, 32)) 
				throw new ArgumentException("SOSEMANUK requires 8 to 32 bytes (64 to 256 bits) of key.", "key");

			KeySetup(key);
			IVSetup(iv);
			_initialised = true;
		}

        public string AlgorithmName {
			get { return Athena.Cryptography.StreamCiphers[SymmetricStreamCipher.Sosemanuk].DisplayName; }
        }

		public int StateSize
		{
			get { return BufferLen; }
		}

        public void Reset () {
            KeySetup(_workingKey);
            IVSetup(_workingIV);
            _initialised = true;
        }

        public byte ReturnByte (byte input) {
            if (!_initialised) 
				throw new InvalidOperationException (AlgorithmName + " not initialised.");
            //CheckLimitExceeded();
		
			if (_streamPtr == BufferLen) {
				makeStreamBlock (_streamBuf, 0);
				_streamPtr = 0;
			}
			return (byte)(input ^ _streamBuf[_streamPtr++]);
        }

        public void ProcessBytes (byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff) {
            if (!_initialised) 
				throw new InvalidOperationException(AlgorithmName + " not initialised.");
			if ((inOff + len) > inBytes.Length) 
				throw new ArgumentException ("Input buffer too short.");
			if ((outOff + len) > outBytes.Length) 
				throw new ArgumentException("Output buffer too short.");
            //CheckLimitExceeded();

			if (len < 1)
				return;

			// Any left over from last time?
			if (_streamPtr < BufferLen) {
				var blen = BufferLen - _streamPtr;
				if (blen > len)
					blen = len;
				inBytes.XOR (inOff, _streamBuf, _streamPtr, outBytes, outOff, blen);
				_streamPtr += blen;
				inOff += blen;
				outOff += blen;
				len -= blen;
			}

			int remainder;
			var blocks = Math.DivRem (len, BufferLen, out remainder);

			for (var i = 0; i < blocks; i++) {
				makeStreamBlock (_streamBuf, 0);
				inBytes.XOR (inOff, _streamBuf, 0, outBytes, outOff, BufferLen);
				inOff += BufferLen;
				outOff += BufferLen;
			}

			if(remainder > 0) {
				makeStreamBlock (_streamBuf, 0);
				inBytes.XOR (inOff, _streamBuf, 0, outBytes, outOff, remainder);
				_streamPtr = remainder;
			}
        }

        public void GetKeystream(byte[] buffer, int offset, int len) {
            if (!_initialised) throw new InvalidOperationException(AlgorithmName + " not initialised.");
			if ((offset + len) > buffer.Length) 
				throw new ArgumentException("Output buffer too short.");
            //CheckLimitExceeded();

            GenerateKeystream(buffer, offset, len);
        }

        private void CheckLimitExceeded() {
            /*
             * if (limitExceeded(len)) {
             *      throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
             * } 
             */
        }

        #region Private implementation

		private static readonly uint[] MulAlpha = new uint[256];
		private static readonly uint[] DivAlpha = new uint[256];

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
                Array.Copy(_streamBuf, _streamPtr, buf, off, blen);
                _streamPtr += blen;
                off += blen;
                len -= blen;
            }
            while (len > 0) {
                if (len >= BufferLen) {
                    makeStreamBlock(buf, off);
                    off += BufferLen;
                    len -= BufferLen;
                } else {
                    makeStreamBlock(_streamBuf, 0);
                    Array.Copy(_streamBuf, 0, buf, off, len);
                    _streamPtr = len;
                    len = 0;
                }
            }
        }

        private static uint RotLeft (uint x, int rot) {
            return (x << rot) | (x >> (32 - rot));
        }

        private static void Encode32LE (uint val, byte[] buf, int off) {
            buf[off] = (byte) val;
            buf[off + 1] = (byte) (val >> 8);
            buf[off + 2] = (byte) (val >> 16);
            buf[off + 3] = (byte) (val >> 24);
        }

        private static uint Decode32LE (byte[] buf, int off) {
			return (buf[off] & (uint)0xFF)
				| ((buf[off + 1] & (uint)0xFF) << 8)
				| ((buf[off + 2] & (uint)0xFF) << 16)
				| ((buf[off + 3] & (uint)0xFF) << 24);
        }

        private void makeStreamBlock(byte[] buf, int off)
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
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v0 = s0;
		    s0 = ((s0 << 8) ^ MulAlpha[(uint)((uint)s0 >> 24)])
			    ^ ((uint)((uint)s3 >> 8) ^ DivAlpha[s3 & 0xFF]) ^ s9;
		    f0 = (s9 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v1 = s1;
		    s1 = ((s1 << 8) ^ MulAlpha[(uint)((uint)s1 >> 24)])
			    ^ ((uint)((uint)s4 >> 8) ^ DivAlpha[s4 & 0xFF]) ^ s0;
		    f1 = (s0 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s3 ^ ((r1 & 0x01) != 0 ? s0 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v2 = s2;
		    s2 = ((s2 << 8) ^ MulAlpha[(uint)((uint)s2 >> 24)])
			    ^ ((uint)((uint)s5 >> 8) ^ DivAlpha[s5 & 0xFF]) ^ s1;
		    f2 = (s1 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v3 = s3;
		    s3 = ((s3 << 8) ^ MulAlpha[(uint)((uint)s3 >> 24)])
			    ^ ((uint)((uint)s6 >> 8) ^ DivAlpha[s6 & 0xFF]) ^ s2;
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
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v0 = s4;
		    s4 = ((s4 << 8) ^ MulAlpha[(uint)((uint)s4 >> 24)])
			    ^ ((uint)((uint)s7 >> 8) ^ DivAlpha[s7 & 0xFF]) ^ s3;
		    f0 = (s3 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v1 = s5;
		    s5 = ((s5 << 8) ^ MulAlpha[(uint)((uint)s5 >> 24)])
			    ^ ((uint)((uint)s8 >> 8) ^ DivAlpha[s8 & 0xFF]) ^ s4;
		    f1 = (s4 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s7 ^ ((r1 & 0x01) != 0 ? s4 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v2 = s6;
		    s6 = ((s6 << 8) ^ MulAlpha[(uint)((uint)s6 >> 24)])
			    ^ ((uint)((uint)s9 >> 8) ^ DivAlpha[s9 & 0xFF]) ^ s5;
		    f2 = (s5 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v3 = s7;
		    s7 = ((s7 << 8) ^ MulAlpha[(uint)((uint)s7 >> 24)])
			    ^ ((uint)((uint)s0 >> 8) ^ DivAlpha[s0 & 0xFF]) ^ s6;
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
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v0 = s8;
		    s8 = ((s8 << 8) ^ MulAlpha[(uint)((uint)s8 >> 24)])
			    ^ ((uint)((uint)s1 >> 8) ^ DivAlpha[s1 & 0xFF]) ^ s7;
		    f0 = (s7 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v1 = s9;
		    s9 = ((s9 << 8) ^ MulAlpha[(uint)((uint)s9 >> 24)])
			    ^ ((uint)((uint)s2 >> 8) ^ DivAlpha[s2 & 0xFF]) ^ s8;
		    f1 = (s8 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s1 ^ ((r1 & 0x01) != 0 ? s8 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v2 = s0;
		    s0 = ((s0 << 8) ^ MulAlpha[(uint)((uint)s0 >> 24)])
			    ^ ((uint)((uint)s3 >> 8) ^ DivAlpha[s3 & 0xFF]) ^ s9;
		    f2 = (s9 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v3 = s1;
		    s1 = ((s1 << 8) ^ MulAlpha[(uint)((uint)s1 >> 24)])
			    ^ ((uint)((uint)s4 >> 8) ^ DivAlpha[s4 & 0xFF]) ^ s0;
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
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v0 = s2;
		    s2 = ((s2 << 8) ^ MulAlpha[(uint)((uint)s2 >> 24)])
			    ^ ((uint)((uint)s5 >> 8) ^ DivAlpha[s5 & 0xFF]) ^ s1;
		    f0 = (s1 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v1 = s3;
		    s3 = ((s3 << 8) ^ MulAlpha[(uint)((uint)s3 >> 24)])
			    ^ ((uint)((uint)s6 >> 8) ^ DivAlpha[s6 & 0xFF]) ^ s2;
		    f1 = (s2 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s5 ^ ((r1 & 0x01) != 0 ? s2 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v2 = s4;
		    s4 = ((s4 << 8) ^ MulAlpha[(uint)((uint)s4 >> 24)])
			    ^ ((uint)((uint)s7 >> 8) ^ DivAlpha[s7 & 0xFF]) ^ s3;
		    f2 = (s3 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v3 = s5;
		    s5 = ((s5 << 8) ^ MulAlpha[(uint)((uint)s5 >> 24)])
			    ^ ((uint)((uint)s8 >> 8) ^ DivAlpha[s8 & 0xFF]) ^ s4;
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
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v0 = s6;
		    s6 = ((s6 << 8) ^ MulAlpha[(uint)((uint)s6 >> 24)])
			    ^ ((uint)((uint)s9 >> 8) ^ DivAlpha[s9 & 0xFF]) ^ s5;
		    f0 = (s5 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v1 = s7;
		    s7 = ((s7 << 8) ^ MulAlpha[(uint)((uint)s7 >> 24)])
			    ^ ((uint)((uint)s0 >> 8) ^ DivAlpha[s0 & 0xFF]) ^ s6;
		    f1 = (s6 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s9 ^ ((r1 & 0x01) != 0 ? s6 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v2 = s8;
		    s8 = ((s8 << 8) ^ MulAlpha[(uint)((uint)s8 >> 24)])
			    ^ ((uint)((uint)s1 >> 8) ^ DivAlpha[s1 & 0xFF]) ^ s7;
		    f2 = (s7 + r1) ^ r2;

		    tt = r1;
		    r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
		    r2 = RotLeft(tt * 0x54655307, 7);
		    v3 = s9;
		    s9 = ((s9 << 8) ^ MulAlpha[(uint)((uint)s9 >> 24)])
                ^ ((uint) ((uint) s2 >> 8) ^ DivAlpha[s2 & 0xFF]) ^ s8;
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

        /// <summary>
        /// Initialise the engine state with key material.
        /// </summary>
        private void KeySetup (byte[] key) {
			if (key.Length == 32) {
				_workingKey = key;
			} else {
				_workingKey = new byte[32];
				Array.Copy(key, 0, _workingKey, 0, key.Length);
				_workingKey[key.Length] = 0x01;
				for (int j = key.Length + 1; j < _workingKey.Length; j++) {
					_workingKey [j] = 0x00;
				}
			}

			uint w0, w1, w2, w3, w4, w5, w6, w7;
            uint r0, r1, r2, r3, r4, tt;
            uint i = 0;

			w0 = _workingKey.LittleEndianToUInt32 (0);
			w1 = _workingKey.LittleEndianToUInt32 (4);
			w2 = _workingKey.LittleEndianToUInt32 (8);
			w3 = _workingKey.LittleEndianToUInt32 (12);
			w4 = _workingKey.LittleEndianToUInt32 (16);
			w5 = _workingKey.LittleEndianToUInt32 (20);
			w6 = _workingKey.LittleEndianToUInt32 (24);
			w7 = _workingKey.LittleEndianToUInt32 (28);

            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (0)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (0 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (0 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (0 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (4)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (4 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (4 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (4 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (8)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (8 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (8 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (8 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (12)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (12 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (12 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (12 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (16)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (16 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (16 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (16 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (20)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (20 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (20 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (20 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (24)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (24 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (24 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (24 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (28)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (28 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (28 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (28 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (32)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (32 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (32 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (32 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (36)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (36 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (36 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (36 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (40)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (40 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (40 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (40 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (44)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (44 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (44 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (44 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (48)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (48 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (48 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (48 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (52)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (52 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (52 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (52 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (56)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (56 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (56 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (56 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (60)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (60 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (60 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (60 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (64)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (64 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (64 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (64 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (68)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (68 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (68 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (68 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (72)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (72 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (72 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (72 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (76)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (76 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (76 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (76 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (80)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (80 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (80 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (80 + 3)));
            w3 = RotLeft(tt, 11);
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
			tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (84)));
            w4 = RotLeft(tt, 11);
			tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (84 + 1)));
            w5 = RotLeft(tt, 11);
			tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (84 + 2)));
            w6 = RotLeft(tt, 11);
			tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (84 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (88)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (88 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (88 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (88 + 3)));
            w3 = RotLeft(tt, 11);
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
            tt = (uint) (w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (92)));
            w4 = RotLeft(tt, 11);
            tt = (uint) (w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (92 + 1)));
            w5 = RotLeft(tt, 11);
            tt = (uint) (w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (92 + 2)));
            w6 = RotLeft(tt, 11);
            tt = (uint) (w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (92 + 3)));
            w7 = RotLeft(tt, 11);
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
            tt = (uint) (w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (96)));
            w0 = RotLeft(tt, 11);
            tt = (uint) (w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (96 + 1)));
            w1 = RotLeft(tt, 11);
            tt = (uint) (w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (96 + 2)));
            w2 = RotLeft(tt, 11);
            tt = (uint) (w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (96 + 3)));
            w3 = RotLeft(tt, 11);
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
				_workingIV = new byte[0];
			if (iv.Length == 16) {
				_workingIV = iv;
			} else {
				_workingIV = new byte[16];
				Array.Copy(iv, 0, _workingIV, 0, iv.Length);
				for (int i = iv.Length; i < _workingIV.Length; i ++)
					_workingIV[i] = 0x00;
			}

            uint r0, r1, r2, r3, r4;

			r0 = Decode32LE(_workingIV, 0);
			r1 = Decode32LE(_workingIV, 4);
			r2 = Decode32LE(_workingIV, 8);
			r3 = Decode32LE(_workingIV, 12);

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
            r1 = RotLeft(r1, 13);
            r2 = RotLeft(r2, 3);
            r4 = r4 ^ r1 ^ r2;
            r0 = r0 ^ r2 ^ (r1 << 3);
            r4 = RotLeft(r4, 1);
            r0 = RotLeft(r0, 7);
            r1 = r1 ^ r4 ^ r0;
            r2 = r2 ^ r0 ^ (r4 << 7);
            r1 = RotLeft(r1, 5);
            r2 = RotLeft(r2, 22);
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
            r2 = RotLeft(r2, 13);
            r0 = RotLeft(r0, 3);
            r1 = r1 ^ r2 ^ r0;
            r4 = r4 ^ r0 ^ (r2 << 3);
            r1 = RotLeft(r1, 1);
            r4 = RotLeft(r4, 7);
            r2 = r2 ^ r1 ^ r4;
            r0 = r0 ^ r4 ^ (r1 << 7);
            r2 = RotLeft(r2, 5);
            r0 = RotLeft(r0, 22);
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
            r0 = RotLeft(r0, 13);
            r1 = RotLeft(r1, 3);
            r4 = r4 ^ r0 ^ r1;
            r3 = r3 ^ r1 ^ (r0 << 3);
            r4 = RotLeft(r4, 1);
            r3 = RotLeft(r3, 7);
            r0 = r0 ^ r4 ^ r3;
            r1 = r1 ^ r3 ^ (r4 << 7);
            r0 = RotLeft(r0, 5);
            r1 = RotLeft(r1, 22);
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
            r4 = RotLeft(r4, 13);
            r3 = RotLeft(r3, 3);
            r1 = r1 ^ r4 ^ r3;
            r2 = r2 ^ r3 ^ (r4 << 3);
            r1 = RotLeft(r1, 1);
            r2 = RotLeft(r2, 7);
            r4 = r4 ^ r1 ^ r2;
            r3 = r3 ^ r2 ^ (r1 << 7);
            r4 = RotLeft(r4, 5);
            r3 = RotLeft(r3, 22);
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
            r1 = RotLeft(r1, 13);
            r4 = RotLeft(r4, 3);
            r0 = r0 ^ r1 ^ r4;
            r2 = r2 ^ r4 ^ (r1 << 3);
            r0 = RotLeft(r0, 1);
            r2 = RotLeft(r2, 7);
            r1 = r1 ^ r0 ^ r2;
            r4 = r4 ^ r2 ^ (r0 << 7);
            r1 = RotLeft(r1, 5);
            r4 = RotLeft(r4, 22);
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
            r0 = RotLeft(r0, 13);
            r1 = RotLeft(r1, 3);
            r2 = r2 ^ r0 ^ r1;
            r4 = r4 ^ r1 ^ (r0 << 3);
            r2 = RotLeft(r2, 1);
            r4 = RotLeft(r4, 7);
            r0 = r0 ^ r2 ^ r4;
            r1 = r1 ^ r4 ^ (r2 << 7);
            r0 = RotLeft(r0, 5);
            r1 = RotLeft(r1, 22);
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
            r0 = RotLeft(r0, 13);
            r3 = RotLeft(r3, 3);
            r2 = r2 ^ r0 ^ r3;
            r1 = r1 ^ r3 ^ (r0 << 3);
            r2 = RotLeft(r2, 1);
            r1 = RotLeft(r1, 7);
            r0 = r0 ^ r2 ^ r1;
            r3 = r3 ^ r1 ^ (r2 << 7);
            r0 = RotLeft(r0, 5);
            r3 = RotLeft(r3, 22);
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
            r4 = RotLeft(r4, 13);
            r2 = RotLeft(r2, 3);
            r1 = r1 ^ r4 ^ r2;
            r0 = r0 ^ r2 ^ (r4 << 3);
            r1 = RotLeft(r1, 1);
            r0 = RotLeft(r0, 7);
            r4 = r4 ^ r1 ^ r0;
            r2 = r2 ^ r0 ^ (r1 << 7);
            r4 = RotLeft(r4, 5);
            r2 = RotLeft(r2, 22);
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
            r1 = RotLeft(r1, 13);
            r2 = RotLeft(r2, 3);
            r3 = r3 ^ r1 ^ r2;
            r4 = r4 ^ r2 ^ (r1 << 3);
            r3 = RotLeft(r3, 1);
            r4 = RotLeft(r4, 7);
            r1 = r1 ^ r3 ^ r4;
            r2 = r2 ^ r4 ^ (r3 << 7);
            r1 = RotLeft(r1, 5);
            r2 = RotLeft(r2, 22);
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
            r2 = RotLeft(r2, 13);
            r4 = RotLeft(r4, 3);
            r1 = r1 ^ r2 ^ r4;
            r3 = r3 ^ r4 ^ (r2 << 3);
            r1 = RotLeft(r1, 1);
            r3 = RotLeft(r3, 7);
            r2 = r2 ^ r1 ^ r3;
            r4 = r4 ^ r3 ^ (r1 << 7);
            r2 = RotLeft(r2, 5);
            r4 = RotLeft(r4, 22);
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
            r4 = RotLeft(r4, 13);
            r1 = RotLeft(r1, 3);
            r3 = r3 ^ r4 ^ r1;
            r0 = r0 ^ r1 ^ (r4 << 3);
            r3 = RotLeft(r3, 1);
            r0 = RotLeft(r0, 7);
            r4 = r4 ^ r3 ^ r0;
            r1 = r1 ^ r0 ^ (r3 << 7);
            r4 = RotLeft(r4, 5);
            r1 = RotLeft(r1, 22);
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
            r3 = RotLeft(r3, 13);
            r0 = RotLeft(r0, 3);
            r1 = r1 ^ r3 ^ r0;
            r2 = r2 ^ r0 ^ (r3 << 3);
            r1 = RotLeft(r1, 1);
            r2 = RotLeft(r2, 7);
            r3 = r3 ^ r1 ^ r2;
            r0 = r0 ^ r2 ^ (r1 << 7);
            r3 = RotLeft(r3, 5);
            r0 = RotLeft(r0, 22);
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
            r1 = RotLeft(r1, 13);
            r3 = RotLeft(r3, 3);
            r4 = r4 ^ r1 ^ r3;
            r2 = r2 ^ r3 ^ (r1 << 3);
            r4 = RotLeft(r4, 1);
            r2 = RotLeft(r2, 7);
            r1 = r1 ^ r4 ^ r2;
            r3 = r3 ^ r2 ^ (r4 << 7);
            r1 = RotLeft(r1, 5);
            r3 = RotLeft(r3, 22);
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
            r4 = RotLeft(r4, 13);
            r1 = RotLeft(r1, 3);
            r2 = r2 ^ r4 ^ r1;
            r3 = r3 ^ r1 ^ (r4 << 3);
            r2 = RotLeft(r2, 1);
            r3 = RotLeft(r3, 7);
            r4 = r4 ^ r2 ^ r3;
            r1 = r1 ^ r3 ^ (r2 << 7);
            r4 = RotLeft(r4, 5);
            r1 = RotLeft(r1, 22);
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
            r4 = RotLeft(r4, 13);
            r0 = RotLeft(r0, 3);
            r2 = r2 ^ r4 ^ r0;
            r1 = r1 ^ r0 ^ (r4 << 3);
            r2 = RotLeft(r2, 1);
            r1 = RotLeft(r1, 7);
            r4 = r4 ^ r2 ^ r1;
            r0 = r0 ^ r1 ^ (r2 << 7);
            r4 = RotLeft(r4, 5);
            r0 = RotLeft(r0, 22);
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
            r3 = RotLeft(r3, 13);
            r2 = RotLeft(r2, 3);
            r1 = r1 ^ r3 ^ r2;
            r4 = r4 ^ r2 ^ (r3 << 3);
            r1 = RotLeft(r1, 1);
            r4 = RotLeft(r4, 7);
            r3 = r3 ^ r1 ^ r4;
            r2 = r2 ^ r4 ^ (r1 << 7);
            r3 = RotLeft(r3, 5);
            r2 = RotLeft(r2, 22);
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
            r1 = RotLeft(r1, 13);
            r2 = RotLeft(r2, 3);
            r0 = r0 ^ r1 ^ r2;
            r3 = r3 ^ r2 ^ (r1 << 3);
            r0 = RotLeft(r0, 1);
            r3 = RotLeft(r3, 7);
            r1 = r1 ^ r0 ^ r3;
            r2 = r2 ^ r3 ^ (r0 << 7);
            r1 = RotLeft(r1, 5);
            r2 = RotLeft(r2, 22);
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
            r2 = RotLeft(r2, 13);
            r3 = RotLeft(r3, 3);
            r1 = r1 ^ r2 ^ r3;
            r0 = r0 ^ r3 ^ (r2 << 3);
            r1 = RotLeft(r1, 1);
            r0 = RotLeft(r0, 7);
            r2 = r2 ^ r1 ^ r0;
            r3 = r3 ^ r0 ^ (r1 << 7);
            r2 = RotLeft(r2, 5);
            r3 = RotLeft(r3, 22);
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
            r3 = RotLeft(r3, 13);
            r1 = RotLeft(r1, 3);
            r0 = r0 ^ r3 ^ r1;
            r4 = r4 ^ r1 ^ (r3 << 3);
            r0 = RotLeft(r0, 1);
            r4 = RotLeft(r4, 7);
            r3 = r3 ^ r0 ^ r4;
            r1 = r1 ^ r4 ^ (r0 << 7);
            r3 = RotLeft(r3, 5);
            r1 = RotLeft(r1, 22);
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
            r0 = RotLeft(r0, 13);
            r4 = RotLeft(r4, 3);
            r1 = r1 ^ r0 ^ r4;
            r2 = r2 ^ r4 ^ (r0 << 3);
            r1 = RotLeft(r1, 1);
            r2 = RotLeft(r2, 7);
            r0 = r0 ^ r1 ^ r2;
            r4 = r4 ^ r2 ^ (r1 << 7);
            r0 = RotLeft(r0, 5);
            r4 = RotLeft(r4, 22);
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
            r1 = RotLeft(r1, 13);
            r0 = RotLeft(r0, 3);
            r3 = r3 ^ r1 ^ r0;
            r2 = r2 ^ r0 ^ (r1 << 3);
            r3 = RotLeft(r3, 1);
            r2 = RotLeft(r2, 7);
            r1 = r1 ^ r3 ^ r2;
            r0 = r0 ^ r2 ^ (r3 << 7);
            r1 = RotLeft(r1, 5);
            r0 = RotLeft(r0, 22);
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
            r3 = RotLeft(r3, 13);
            r1 = RotLeft(r1, 3);
            r2 = r2 ^ r3 ^ r1;
            r0 = r0 ^ r1 ^ (r3 << 3);
            r2 = RotLeft(r2, 1);
            r0 = RotLeft(r0, 7);
            r3 = r3 ^ r2 ^ r0;
            r1 = r1 ^ r0 ^ (r2 << 7);
            r3 = RotLeft(r3, 5);
            r1 = RotLeft(r1, 22);
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
            r3 = RotLeft(r3, 13);
            r4 = RotLeft(r4, 3);
            r2 = r2 ^ r3 ^ r4;
            r1 = r1 ^ r4 ^ (r3 << 3);
            r2 = RotLeft(r2, 1);
            r1 = RotLeft(r1, 7);
            r3 = r3 ^ r2 ^ r1;
            r4 = r4 ^ r1 ^ (r2 << 7);
            r3 = RotLeft(r3, 5);
            r4 = RotLeft(r4, 22);
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
            r0 = RotLeft(r0, 13);
            r2 = RotLeft(r2, 3);
            r1 = r1 ^ r0 ^ r2;
            r3 = r3 ^ r2 ^ (r0 << 3);
            r1 = RotLeft(r1, 1);
            r3 = RotLeft(r3, 7);
            r0 = r0 ^ r1 ^ r3;
            r2 = r2 ^ r3 ^ (r1 << 7);
            r0 = RotLeft(r0, 5);
            r2 = RotLeft(r2, 22);
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
