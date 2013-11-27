using System;
using ObscurCore.Cryptography.Ciphers.Block.Modes.GCM;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
    /// <summary>
    ///     Implements the Galois/Counter mode (GCM) detailed in
    ///     NIST Special Publication 800-38D.
    /// </summary>
    public class GcmBlockCipher
        : IAeadBlockCipher
    {
        private const int blockSize = 16;
        private static readonly byte[] Zeroes = new byte[blockSize];

        private readonly IBlockCipher _cipher;
        private readonly IGcmMultiplier _multiplier;

        // These fields are set by Init and not modified by processing
        private byte[] A;
        private byte[] H;
        private byte[] J0;

        // These fields are modified during processing
        private byte[] S;
        private byte[] bufBlock;
        private int bufOff;
        private byte[] counter;
        private bool _forEncryption;
        private byte[] initS;
        private KeyParameter keyParam;
        private byte[] macBlock;
        private int macSize;
        private byte[] nonce;
        private ulong totalLength;

        public GcmBlockCipher(
            IBlockCipher c)
            : this(c, null) {}

        public GcmBlockCipher(
            IBlockCipher c,
            IGcmMultiplier m) {
            if (c.BlockSize != blockSize)
                throw new ArgumentException("cipher required with a block size of " + blockSize + ".");

            if (m == null) {
                // TODO Consider a static property specifying default multiplier
                m = new Tables8kGcmMultiplier();
            }

            _cipher = c;
            _multiplier = m;
        }

        public virtual string AlgorithmName {
            get { return _cipher.AlgorithmName + "/GCM"; }
        }

        public virtual int BlockSize {
            get { return blockSize; }
        }

        public virtual void Init(
            bool forEncryption,
            ICipherParameters parameters) {
            this._forEncryption = forEncryption;
            macBlock = null;

            if (parameters is AeadParameters) {
                var param = (AeadParameters) parameters;

                nonce = param.GetNonce();
                A = param.GetAssociatedText();

                int macSizeBits = param.MacSize;
                if (macSizeBits < 96 || macSizeBits > 128 || macSizeBits%8 != 0) {
                    throw new ArgumentException("Invalid value for MAC size: " + macSizeBits);
                }

                macSize = macSizeBits/8;
                keyParam = param.Key;
            } else if (parameters is ParametersWithIV) {
                var param = (ParametersWithIV) parameters;

                nonce = param.GetIV();
                A = null;
                macSize = 16;
                keyParam = (KeyParameter) param.Parameters;
            } else {
                throw new ArgumentException("invalid parameters passed to GCM");
            }

            int bufLength = forEncryption ? blockSize : (blockSize + macSize);
            bufBlock = new byte[bufLength];

            if (nonce == null || nonce.Length < 1) {
                throw new ArgumentException("IV must be at least 1 byte");
            }

            if (A == null) {
                // Avoid lots of null checks
                A = new byte[0];
            }

            // Cipher always used in forward mode
            _cipher.Init(true, keyParam);

            // TODO This should be configurable by Init parameters
            // (but must be 16 if nonce length not 12) (BlockSize?)
//			this.tagLength = 16;

            H = new byte[blockSize];
            _cipher.ProcessBlock(H, 0, H, 0);
            _multiplier.Init(H);

            initS = gHASH(A);

            if (nonce.Length == 12) {
                J0 = new byte[16];
                Array.Copy(nonce, 0, J0, 0, nonce.Length);
                J0[15] = 0x01;
            } else {
                J0 = gHASH(nonce);
                var X = new byte[16];
                packLength((ulong) nonce.Length*8UL, X, 8);
                GcmUtilities.Xor(J0, X);
                _multiplier.MultiplyH(J0);
            }

            S = Arrays.Clone(initS);
            counter = Arrays.Clone(J0);
            bufOff = 0;
            totalLength = 0;
        }

        public virtual byte[] GetMac() {
            return Arrays.Clone(macBlock);
        }

        public virtual int GetOutputSize(
            int len) {
            if (_forEncryption) {
                return len + bufOff + macSize;
            }

            return len + bufOff - macSize;
        }

        public virtual int GetUpdateOutputSize(
            int len) {
            return ((len + bufOff)/blockSize)*blockSize;
        }

        public virtual int ProcessByte(
            byte input,
            byte[] output,
            int outOff) {
            return Process(input, output, outOff);
        }

        public virtual int ProcessBytes(
            byte[] input,
            int inOff,
            int len,
            byte[] output,
            int outOff) {
            int resultLen = 0;

            for (int i = 0; i != len; i++) {
//				resultLen += Process(input[inOff + i], output, outOff + resultLen);
                bufBlock[bufOff++] = input[inOff + i];

                if (bufOff == bufBlock.Length) {
                    gCTRBlock(bufBlock, blockSize, output, outOff + resultLen);
                    if (!_forEncryption) {
                        Array.Copy(bufBlock, blockSize, bufBlock, 0, macSize);
                    }
//		            bufOff = 0;
                    bufOff = bufBlock.Length - blockSize;
//		            return bufBlock.Length;
                    resultLen += blockSize;
                }
            }

            return resultLen;
        }

        public int DoFinal(byte[] output, int outOff) {
            int extra = bufOff;
            if (!_forEncryption) {
                if (extra < macSize)
                    throw new InvalidCipherTextException("data too short");

                extra -= macSize;
            }

            if (extra > 0) {
                var tmp = new byte[blockSize];
                Array.Copy(bufBlock, 0, tmp, 0, extra);
                gCTRBlock(tmp, extra, output, outOff);
            }

            // Final gHASH
            var X = new byte[16];
            packLength((ulong) A.Length*8UL, X, 0);
            packLength(totalLength*8UL, X, 8);

            GcmUtilities.Xor(S, X);
            _multiplier.MultiplyH(S);

            // TODO Fix this if tagLength becomes configurable
            // T = MSBt(GCTRk(J0,S))
            var tag = new byte[blockSize];
            _cipher.ProcessBlock(J0, 0, tag, 0);
            GcmUtilities.Xor(tag, S);

            int resultLen = extra;

            // We place into macBlock our calculated value for T
            macBlock = new byte[macSize];
            Array.Copy(tag, 0, macBlock, 0, macSize);

            if (_forEncryption) {
                // Append T to the message
                Array.Copy(macBlock, 0, output, outOff + bufOff, macSize);
                resultLen += macSize;
            } else {
                // Retrieve the T value from the message and compare to calculated one
                var msgMac = new byte[macSize];
                Array.Copy(bufBlock, extra, msgMac, 0, macSize);
                if (!Arrays.ConstantTimeAreEqual(macBlock, msgMac))
                    throw new InvalidCipherTextException("mac check in GCM failed");
            }

            Reset(false);

            return resultLen;
        }

        public virtual void Reset() {
            Reset(true);
        }

        private int Process(
            byte input,
            byte[] output,
            int outOff) {
            bufBlock[bufOff++] = input;

            if (bufOff == bufBlock.Length) {
                gCTRBlock(bufBlock, blockSize, output, outOff);
                if (!_forEncryption) {
                    Array.Copy(bufBlock, blockSize, bufBlock, 0, macSize);
                }
                //            bufOff = 0;
                bufOff = bufBlock.Length - blockSize;
                //            return bufBlock.Length;
                return blockSize;
            }

            return 0;
        }

        private void Reset(
            bool clearMac) {
            S = Arrays.Clone(initS);
            counter = Arrays.Clone(J0);
            bufOff = 0;
            totalLength = 0;

            if (bufBlock != null) {
                Array.Clear(bufBlock, 0, bufBlock.Length);
            }

            if (clearMac) {
                macBlock = null;
            }

            _cipher.Reset();
        }

        private void gCTRBlock(byte[] buf, int bufCount, byte[] output, int outOff) {
//			inc(counter);
            for (int i = 15; i >= 12; --i) {
                if (++counter[i] != 0) break;
            }

            var tmp = new byte[blockSize];
            _cipher.ProcessBlock(counter, 0, tmp, 0);

            byte[] hashBytes;
            if (_forEncryption) {
                Array.Copy(Zeroes, bufCount, tmp, bufCount, blockSize - bufCount);
                hashBytes = tmp;
            } else {
                hashBytes = buf;
            }

            for (int i = bufCount - 1; i >= 0; --i) {
                tmp[i] ^= buf[i];
                output[outOff + i] = tmp[i];
            }

//			gHASHBlock(hashBytes);
            GcmUtilities.Xor(S, hashBytes);
            _multiplier.MultiplyH(S);

            totalLength += (ulong) bufCount;
        }

        private byte[] gHASH(byte[] b) {
            var Y = new byte[16];

            for (int pos = 0; pos < b.Length; pos += 16) {
                var X = new byte[16];
                int num = Math.Min(b.Length - pos, 16);
                Array.Copy(b, pos, X, 0, num);
                GcmUtilities.Xor(Y, X);
                _multiplier.MultiplyH(Y);
            }

            return Y;
        }

//		private void gHASHBlock(byte[] block)
//		{
//			GcmUtilities.Xor(S, block);
//			multiplier.MultiplyH(S);
//		}

//		private static void inc(byte[] block)
//		{
//			for (int i = 15; i >= 12; --i)
//			{
//				if (++block[i] != 0) break;
//			}
//		}

        private static void packLength(ulong len, byte[] bs, int off) {
            Pack.UInt32_To_BE((uint) (len >> 32), bs, off);
            Pack.UInt32_To_BE((uint) len, bs, off + 4);
        }
    }
}