using System;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
    public sealed class Blake2BCore
	{
		private bool _isInitialized;
		
		private int _bufferFilled;
		private readonly byte[] _buf = new byte[128];
		
		private readonly ulong[] _m = new ulong[16];
		private readonly ulong[] _h = new ulong[8];
		private ulong _counter0;
		private ulong _counter1;
		private ulong _finalizationFlag0;
		private ulong _finalizationFlag1;
		
		private const int NumberOfRounds = 12;
		private const int BlockSizeInBytes = 128;
		
		const ulong IV0 = 0x6A09E667F3BCC908UL;
		const ulong IV1 = 0xBB67AE8584CAA73BUL;
		const ulong IV2 = 0x3C6EF372FE94F82BUL;
		const ulong IV3 = 0xA54FF53A5F1D36F1UL;
		const ulong IV4 = 0x510E527FADE682D1UL;
		const ulong IV5 = 0x9B05688C2B3E6C1FUL;
		const ulong IV6 = 0x1F83D9ABFB41BD6BUL;
		const ulong IV7 = 0x5BE0CD19137E2179UL;
		
		private static readonly int[] Sigma = new int[NumberOfRounds * 16] {
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
			11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
			7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
			9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
			2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
			12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
			13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
			6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
			10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
		};

        public sealed class Blake2BConfig : ICloneable
        {
            public byte[] Personalization { get; set; }
            public byte[] Salt { get; set; }
            public byte[] Key { get; set; }
            public int OutputSizeInBytes { get; set; }
            public int OutputSizeInBits
            {
                get { return OutputSizeInBytes * 8; }
                set
                {
                    if (value % 8 == 0)
                        throw new ArgumentException("Output size must be a multiple of 8 bits");
                    OutputSizeInBytes = value / 8;
                }
            }

            public Blake2BConfig()
            {
                OutputSizeInBytes = 64;
            }

            public Blake2BConfig Clone()
            {
                var result = new Blake2BConfig();
                result.OutputSizeInBytes = OutputSizeInBytes;
                if (Key != null)
                    result.Key = (byte[])Key.Clone();
                if (Personalization != null)
                    result.Personalization = (byte[])Personalization.Clone();
                if (Salt != null)
                    result.Salt = (byte[])Salt.Clone();
                return result;
            }

            object ICloneable.Clone()
            {
                return Clone();
            }
        }

        #region IV builder
        //private static readonly Blake2BTreeConfig SequentialTreeConfig = new Blake2BTreeConfig() { IntermediateHashSize = 0, LeafSize = 0, FanOut = 1, MaxHeight = 1 };

        public static ulong[] ConfigB(Blake2BConfig config)
        {
            //bool isSequential = treeConfig == null;
            //if (isSequential)
            //    treeConfig = SequentialTreeConfig;
            var rawConfig = new ulong[8];
            //var result = new ulong[8]; //TODO: Investigate this

            //digest length
            if (config.OutputSizeInBytes <= 0 | config.OutputSizeInBytes > 64)
                throw new ArgumentOutOfRangeException("config.OutputSize");
            rawConfig[0] |= (ulong)(uint)config.OutputSizeInBytes;

            //Key length
            if (config.Key != null) {
                if (config.Key.Length > 64)
                    throw new ArgumentException("Key too long", "config.Key");
                rawConfig[0] |= (ulong)((uint)config.Key.Length << 8);
            }
            // FanOut
            //rawConfig[0] |= (uint)treeConfig.FanOut << 16;
            rawConfig[0] |= (uint)1 << 16;
            // Depth
            //rawConfig[0] |= (uint)treeConfig.MaxHeight << 24;
            rawConfig[0] |= (uint)1 << 24;
            // Leaf length
            rawConfig[0] |= ((ulong)(uint)0) << 32;
            // Inner length
            //if (!isSequential && (treeConfig.IntermediateHashSize <= 0 || treeConfig.IntermediateHashSize > 64))
            //    throw new ArgumentOutOfRangeException("treeConfig.TreeIntermediateHashSize");
            rawConfig[2] |= (uint)0 << 8;
            // Salt
            if (config.Salt != null) {
                if (config.Salt.Length != 16)
                    throw new ArgumentException("config.Salt has invalid length");
                //rawConfig[4] = Blake2BCore.BytesToUInt64(config.Salt, 0);
                //rawConfig[5] = Blake2BCore.BytesToUInt64(config.Salt, 8);
                rawConfig[4] = config.Salt.LittleEndianToUInt64();
                rawConfig[5] = config.Salt.LittleEndianToUInt64(8);
            }
            // Personalization
            if (config.Personalization != null) {
                if (config.Personalization.Length != 16)
                    throw new ArgumentException("config.Personalization has invalid length");
                //rawConfig[6] = Blake2BCore.BytesToUInt64(config.Personalization, 0);
                //rawConfig[6] = Blake2BCore.BytesToUInt64(config.Personalization, 8);
                rawConfig[6] = config.Personalization.LittleEndianToUInt64();
                rawConfig[7] = config.Personalization.LittleEndianToUInt64(8);
            }

            return rawConfig;
        }
        #endregion

        //internal static ulong BytesToUInt64(byte[] buf, int offset)
        //{
        //    return
        //        ((ulong)buf[offset + 7] << 7 * 8 |
        //         ((ulong)buf[offset + 6] << 6 * 8) |
        //         ((ulong)buf[offset + 5] << 5 * 8) |
        //         ((ulong)buf[offset + 4] << 4 * 8) |
        //         ((ulong)buf[offset + 3] << 3 * 8) |
        //         ((ulong)buf[offset + 2] << 2 * 8) |
        //         ((ulong)buf[offset + 1] << 1 * 8) |
        //         ((ulong)buf[offset]));
        //}
		
        //private static void UInt64ToBytes(ulong value, byte[] buf, int offset)
        //{
        //    buf[offset + 7] = (byte)(value >> 7 * 8);
        //    buf[offset + 6] = (byte)(value >> 6 * 8);
        //    buf[offset + 5] = (byte)(value >> 5 * 8);
        //    buf[offset + 4] = (byte)(value >> 4 * 8);
        //    buf[offset + 3] = (byte)(value >> 3 * 8);
        //    buf[offset + 2] = (byte)(value >> 2 * 8);
        //    buf[offset + 1] = (byte)(value >> 1 * 8);
        //    buf[offset] = (byte)value;
        //}

		public void Initialize(ulong[] config)
		{
			if (config == null)
				throw new ArgumentNullException("config");
			if (config.Length != 8)
				throw new ArgumentException("config length must be 8 words");
			_isInitialized = true;
			
			_h[0] = IV0;
			_h[1] = IV1;
			_h[2] = IV2;
			_h[3] = IV3;
			_h[4] = IV4;
			_h[5] = IV5;
			_h[6] = IV6;
			_h[7] = IV7;
			
			_counter0 = 0;
			_counter1 = 0;
			_finalizationFlag0 = 0;
			_finalizationFlag1 = 0;
			
			_bufferFilled = 0;
			
			Array.Clear(_buf, 0, _buf.Length);
			
			for (int i = 0; i < 8; i++)
				_h[i] ^= config[i];
		}
		
		public void HashCore(byte[] array, int start, int count)
		{
			if (!_isInitialized)
				throw new InvalidOperationException("Not initialized");
			if (array == null)
				throw new ArgumentNullException("array");
			if (start < 0)
				throw new ArgumentOutOfRangeException("start");
			if (count < 0)
				throw new ArgumentOutOfRangeException("count");
			if ((long)start + (long)count > array.Length)
				throw new ArgumentOutOfRangeException("start+count");
			int offset = start;
			int bufferRemaining = BlockSizeInBytes - _bufferFilled;
			
			if ((_bufferFilled > 0) && (count > bufferRemaining))
			{
				//Array.Copy(array, offset, _buf, _bufferFilled, bufferRemaining);
                array.CopyBytes(offset, _buf, _bufferFilled, bufferRemaining);
				_counter0 += BlockSizeInBytes;
				if (_counter0 == 0)
					_counter1++;
				Compress(_buf, 0);
				offset += bufferRemaining;
				count -= bufferRemaining;
				_bufferFilled = 0;
			}
			
			while (count > BlockSizeInBytes)
			{
				_counter0 += BlockSizeInBytes;
				if (_counter0 == 0)
					_counter1++;
				Compress(array, offset);
				offset += BlockSizeInBytes;
				count -= BlockSizeInBytes;
			}
			
			if (count > 0)
			{
				//Array.Copy(array, offset, _buf, _bufferFilled, count);
                array.CopyBytes(offset, _buf, _bufferFilled, count);
				_bufferFilled += count;
			}
		}
		
		public byte[] HashFinal()
		{
			return HashFinal(false);
		}
		
		public byte[] HashFinal(bool isEndOfLayer)
		{
			if (!_isInitialized)
				throw new InvalidOperationException("Not initialized");
			_isInitialized = false;
			
			//Last compression
			_counter0 += (uint)_bufferFilled;
			_finalizationFlag0 = ulong.MaxValue;
			if (isEndOfLayer)
				_finalizationFlag1 = ulong.MaxValue;
			for (int i = _bufferFilled; i < _buf.Length; i++)
				_buf[i] = 0;
			Compress(_buf, 0);
			
			//Output
			byte[] hash = new byte[64];
		    for (int i = 0; i < 8; ++i)
		        //UInt64ToBytes(_h[i], hash, i << 3);
		        _h[i].ToLittleEndian(hash, i << 3);
			return hash;
		}

        #region Compression function (fully unrolled)
        private void Compress(byte[] block, int start)
        {
            var h = _h;
            var m = _m;

            if (BitConverter.IsLittleEndian) {
                Buffer.BlockCopy(block, start, m, 0, BlockSizeInBytes);
            } else {
                for (int i = 0; i < 16; ++i)
                    //m[i] = BytesToUInt64(block, start + (i << 3));
                    m[i] = block.LittleEndianToUInt64(start + (i << 3));
            }

            Buffer.BlockCopy(block, start, m, 0, BlockSizeInBytes);

            /*var m0 = m[0];
            var m1 = m[1];
            var m2 = m[2];
            var m3 = m[3];
            var m4 = m[4];
            var m5 = m[5];
            var m6 = m[6];
            var m7 = m[7];
            var m8 = m[8];
            var m9 = m[9];
            var m10 = m[10];
            var m11 = m[11];
            var m12 = m[12];
            var m13 = m[13];
            var m14 = m[14];
            var m15 = m[15];*/

            var v0 = h[0];
            var v1 = h[1];
            var v2 = h[2];
            var v3 = h[3];
            var v4 = h[4];
            var v5 = h[5];
            var v6 = h[6];
            var v7 = h[7];

            var v8 = IV0;
            var v9 = IV1;
            var v10 = IV2;
            var v11 = IV3;
            var v12 = IV4 ^ _counter0;
            var v13 = IV5 ^ _counter1;
            var v14 = IV6 ^ _finalizationFlag0;
            var v15 = IV7 ^ _finalizationFlag1;

            // Rounds

            //System.Diagnostics.Debugger.Break();

            // ##### Round(0) #####
            // G(0, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[0];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[1];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(0, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[2];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[3];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(0, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[4];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[5];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(0, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[6];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[7];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(0, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[8];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[9];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(0, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[10];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[11];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(0, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[12];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[13];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(0, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[14];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[15];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(1) #####
            // G(1, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[14];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[10];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(1, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[4];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[8];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(1, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[9];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[15];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(1, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[13];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[6];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(1, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[1];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[12];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(1, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[0];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[2];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(1, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[11];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[7];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(1, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[5];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[3];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(2) #####
            // G(2, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[11];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[8];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(2, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[12];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[0];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(2, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[5];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[2];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(2, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[15];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[13];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(2, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[10];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[14];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(2, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[3];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[6];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(2, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[7];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[1];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(2, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[9];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[4];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(3) #####
            // G(3, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[7];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[9];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(3, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[3];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[1];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(3, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[13];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[12];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(3, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[11];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[14];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(3, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[2];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[6];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(3, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[5];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[10];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(3, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[4];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[0];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(3, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[15];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[8];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(4) #####
            // G(4, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[9];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[0];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(4, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[5];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[7];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(4, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[2];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[4];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(4, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[10];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[15];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(4, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[14];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[1];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(4, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[11];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[12];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(4, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[6];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[8];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(4, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[3];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[13];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(5) #####
            // G(5, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[2];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[12];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(5, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[6];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[10];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(5, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[0];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[11];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(5, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[8];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[3];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(5, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[4];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[13];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(5, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[7];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[5];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(5, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[15];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[14];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(5, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[1];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[9];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(6) #####
            // G(6, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[12];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[5];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(6, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[1];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[15];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(6, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[14];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[13];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(6, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[4];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[10];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(6, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[0];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[7];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(6, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[6];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[3];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(6, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[9];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[2];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(6, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[8];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[11];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(7) #####
            // G(7, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[13];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[11];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(7, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[7];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[14];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(7, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[12];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[1];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(7, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[3];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[9];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(7, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[5];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[0];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(7, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[15];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[4];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(7, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[8];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[6];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(7, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[2];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[10];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(8) #####
            // G(8, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[6];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[15];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(8, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[14];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[9];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(8, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[11];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[3];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(8, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[0];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[8];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(8, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[12];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[2];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(8, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[13];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[7];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(8, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[1];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[4];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(8, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[10];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[5];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(9) #####
            // G(9, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[10];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[2];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(9, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[8];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[4];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(9, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[7];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[6];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(9, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[1];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[5];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(9, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[15];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[11];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(9, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[9];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[14];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(9, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[3];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[12];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(9, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[13];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[0];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(10) #####
            // G(10, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[0];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[1];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(10, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[2];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[3];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(10, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[4];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[5];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(10, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[6];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[7];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(10, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[8];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[9];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(10, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[10];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[11];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(10, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[12];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[13];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(10, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[14];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[15];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));


            // ##### Round(11) #####
            // G(11, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m[14];
            v12 ^= v0;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v0 = v0 + v4 + m[10];
            v12 ^= v0;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v8 = v8 + v12;
            v4 ^= v8;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            // G(11, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m[4];
            v13 ^= v1;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v1 = v1 + v5 + m[8];
            v13 ^= v1;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v9 = v9 + v13;
            v5 ^= v9;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(11, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m[9];
            v14 ^= v2;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v2 = v2 + v6 + m[15];
            v14 ^= v2;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v10 = v10 + v14;
            v6 ^= v10;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(11, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m[13];
            v15 ^= v3;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v3 = v3 + v7 + m[6];
            v15 ^= v3;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v11 = v11 + v15;
            v7 ^= v11;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(11, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m[1];
            v15 ^= v0;
            v15 = ((v15 >> 32) | (v15 << (64 - 32)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 24) | (v5 << (64 - 24)));
            v0 = v0 + v5 + m[12];
            v15 ^= v0;
            v15 = ((v15 >> 16) | (v15 << (64 - 16)));
            v10 = v10 + v15;
            v5 ^= v10;
            v5 = ((v5 >> 63) | (v5 << (64 - 63)));

            // G(11, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m[0];
            v12 ^= v1;
            v12 = ((v12 >> 32) | (v12 << (64 - 32)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 24) | (v6 << (64 - 24)));
            v1 = v1 + v6 + m[2];
            v12 ^= v1;
            v12 = ((v12 >> 16) | (v12 << (64 - 16)));
            v11 = v11 + v12;
            v6 ^= v11;
            v6 = ((v6 >> 63) | (v6 << (64 - 63)));

            // G(11, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m[11];
            v13 ^= v2;
            v13 = ((v13 >> 32) | (v13 << (64 - 32)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 24) | (v7 << (64 - 24)));
            v2 = v2 + v7 + m[7];
            v13 ^= v2;
            v13 = ((v13 >> 16) | (v13 << (64 - 16)));
            v8 = v8 + v13;
            v7 ^= v8;
            v7 = ((v7 >> 63) | (v7 << (64 - 63)));

            // G(11, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m[5];
            v14 ^= v3;
            v14 = ((v14 >> 32) | (v14 << (64 - 32)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 24) | (v4 << (64 - 24)));
            v3 = v3 + v4 + m[3];
            v14 ^= v3;
            v14 = ((v14 >> 16) | (v14 << (64 - 16)));
            v9 = v9 + v14;
            v4 ^= v9;
            v4 = ((v4 >> 63) | (v4 << (64 - 63)));

            //Finalization
            h[0] ^= v0 ^ v8;
            h[1] ^= v1 ^ v9;
            h[2] ^= v2 ^ v10;
            h[3] ^= v3 ^ v11;
            h[4] ^= v4 ^ v12;
            h[5] ^= v5 ^ v13;
            h[6] ^= v6 ^ v14;
            h[7] ^= v7 ^ v15;
        }
#endregion
	}
}
