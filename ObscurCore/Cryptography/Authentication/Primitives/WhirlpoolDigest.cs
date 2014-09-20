using System;
using System.Diagnostics;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
    internal interface IDirectIoDigest
    {
        
    }

    class WhirlpoolDigest : IHash
    {
        #region Consts

        private const int BlockSizeBytes = 64;
        private const int ROUNDS = 10;
        private const uint REDUCTION_POLYNOMIAL = 0x011D;

        private static readonly uint[] s_SBOX =
        {
            0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
            0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
            0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
            0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
            0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
            0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
            0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
            0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
            0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
            0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
            0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
            0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
            0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
            0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
            0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
            0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
        };

        private static readonly ulong[] s_C0 = new ulong[256];
        private static readonly ulong[] s_C1 = new ulong[256];
        private static readonly ulong[] s_C2 = new ulong[256];
        private static readonly ulong[] s_C3 = new ulong[256];
        private static readonly ulong[] s_C4 = new ulong[256];
        private static readonly ulong[] s_C5 = new ulong[256];
        private static readonly ulong[] s_C6 = new ulong[256];
        private static readonly ulong[] s_C7 = new ulong[256];

        private static ulong[] s_rc = new ulong[ROUNDS + 1];

        static WhirlpoolDigest()
        {
            for (int i = 0; i < 256; i++)
            {
                uint v1 = s_SBOX[i];
                uint v2 = maskWithReductionPolynomial(v1 << 1);
                uint v4 = maskWithReductionPolynomial(v2 << 1);
                uint v5 = v4 ^ v1;
                uint v8 = maskWithReductionPolynomial(v4 << 1);
                uint v9 = v8 ^ v1;

                s_C0[i] = packIntoULong(v1, v1, v4, v1, v8, v5, v2, v9);
                s_C1[i] = packIntoULong(v9, v1, v1, v4, v1, v8, v5, v2);
                s_C2[i] = packIntoULong(v2, v9, v1, v1, v4, v1, v8, v5);
                s_C3[i] = packIntoULong(v5, v2, v9, v1, v1, v4, v1, v8);
                s_C4[i] = packIntoULong(v8, v5, v2, v9, v1, v1, v4, v1);
                s_C5[i] = packIntoULong(v1, v8, v5, v2, v9, v1, v1, v4);
                s_C6[i] = packIntoULong(v4, v1, v8, v5, v2, v9, v1, v1);
                s_C7[i] = packIntoULong(v1, v4, v1, v8, v5, v2, v9, v1);
            }

            s_rc[0] = 0;

            for (int r = 1; r <= ROUNDS; r++)
            {
                int i = 8 * (r - 1);
                s_rc[r] = (s_C0[i] & 0xff00000000000000) ^
                          (s_C1[i + 1] & 0x00ff000000000000) ^
                          (s_C2[i + 2] & 0x0000ff0000000000) ^
                          (s_C3[i + 3] & 0x000000ff00000000) ^
                          (s_C4[i + 4] & 0x00000000ff000000) ^
                          (s_C5[i + 5] & 0x0000000000ff0000) ^
                          (s_C6[i + 6] & 0x000000000000ff00) ^
                          (s_C7[i + 7] & 0x00000000000000ff);
            }

        }

        private static ulong packIntoULong(uint b7, uint b6, uint b5, uint b4, uint b3, uint b2, uint b1, uint b0)
        {
            return ((ulong)b7 << 56) ^
                   ((ulong)b6 << 48) ^
                   ((ulong)b5 << 40) ^
                   ((ulong)b4 << 32) ^
                   ((ulong)b3 << 24) ^
                   ((ulong)b2 << 16) ^
                   ((ulong)b1 << 8) ^
                   b0;
        }

        private static uint maskWithReductionPolynomial(uint input)
        {
            if (input >= 0x100)
                input ^= REDUCTION_POLYNOMIAL;
            return input;
        }

        #endregion

        private readonly ulong[] m_hash = new ulong[8];

        private byte[] _buffer = new byte[BlockSizeBytes];
        private int _bufferFilled;
        private int m_processed_bytes;

        public WhirlpoolDigest()
        {
        }

        public string AlgorithmName
        {
            get { return "Whirlpool"; }
        }

        public int DigestSize
        {
            get { return 64; }
        }

        public int ByteLength
        {
            get { return BlockSizeBytes; }
        }

        public void Update(byte input) {
            if (_bufferFilled == BlockSizeBytes) {
				Transform(_buffer, 0);
				_bufferFilled = 0;
			}

            _buffer[_bufferFilled++] = input;
            m_processed_bytes++;
        }

        public void BlockUpdate(byte[] input, int inOff, int len) {

            int offset = inOff;
            int count = len;
            int bufferRemaining = BlockSizeBytes - _bufferFilled;
			
			if ((_bufferFilled > 0) && (count > bufferRemaining))
			{
                input.CopyBytes(offset, _buffer, _bufferFilled, bufferRemaining);
				Transform(_buffer, 0);
				offset += bufferRemaining;
				count -= bufferRemaining;
				_bufferFilled = 0;
			}
			
			while (count > BlockSizeBytes)
			{
				Transform(input, offset);
				offset += BlockSizeBytes;
				count -= BlockSizeBytes;
			}
			
			if (count > 0)
			{
                input.CopyBytes(offset, _buffer, _bufferFilled, count);
				_bufferFilled += count;
			}

            m_processed_bytes += len;
        }

        //private static void ConvertBytesToULongsSwapOrder(byte[] a_in, int a_index, int a_length, ulong[] a_out)
        //{
        //    for (int i = 0; a_length > 0; a_length -= 8)
        //    {
        //        a_out[i++] =
        //            (((ulong)a_in[a_index++] << 56) |
        //            ((ulong)a_in[a_index++] << 48) |
        //            ((ulong)a_in[a_index++] << 40) |
        //            ((ulong)a_in[a_index++] << 32) |
        //            ((ulong)a_in[a_index++] << 24) |
        //            ((ulong)a_in[a_index++] << 16) |
        //            ((ulong)a_in[a_index++] << 8) |
        //            ((ulong)a_in[a_index++]));
        //    }
        //}

#if INCLUDE_UNSAFE
        private void Transform(byte[] input, int offset)
        {
            unsafe {
                ulong* k = stackalloc ulong[8];
                ulong* m = stackalloc ulong[8];

                ulong* temp = stackalloc ulong[8];
                ulong* data = stackalloc ulong[8];

                //ConvertBytesToULongsSwapOrder(input, offset, BlockSizeBytes, data);
                for (int i = 0; i < 8; i++) {
                    data[i] = input.BigEndianToUInt64(offset + (i * sizeof(ulong)));
                }

                for (int i = 0; i < 8; i++) {
                    k[i] = m_hash[i];
                    temp[i] = data[i] ^ k[i];
                }

                for (int round = 1; round <= ROUNDS; round++) {
                    for (int i = 0; i < 8; i++) {
                        m[i] = 0;
                        m[i] ^= s_C0[(byte)(k[(i - 0) & 7] >> 56)];
                        m[i] ^= s_C1[(byte)(k[(i - 1) & 7] >> 48)];
                        m[i] ^= s_C2[(byte)(k[(i - 2) & 7] >> 40)];
                        m[i] ^= s_C3[(byte)(k[(i - 3) & 7] >> 32)];
                        m[i] ^= s_C4[(byte)(k[(i - 4) & 7] >> 24)];
                        m[i] ^= s_C5[(byte)(k[(i - 5) & 7] >> 16)];
                        m[i] ^= s_C6[(byte)(k[(i - 6) & 7] >> 8)];
                        m[i] ^= s_C7[(byte)(k[(i - 7) & 7])];
                    }

                    Copy(m, k, 8);

                    k[0] ^= s_rc[round];

                    for (int i = 0; i < 8; i++) {
                        m[i] = k[i];

                        m[i] ^= s_C0[(byte)(temp[(i - 0) & 7] >> 56)];
                        m[i] ^= s_C1[(byte)(temp[(i - 1) & 7] >> 48)];
                        m[i] ^= s_C2[(byte)(temp[(i - 2) & 7] >> 40)];
                        m[i] ^= s_C3[(byte)(temp[(i - 3) & 7] >> 32)];
                        m[i] ^= s_C4[(byte)(temp[(i - 4) & 7] >> 24)];
                        m[i] ^= s_C5[(byte)(temp[(i - 5) & 7] >> 16)];
                        m[i] ^= s_C6[(byte)(temp[(i - 6) & 7] >> 8)];
                        m[i] ^= s_C7[(byte)(temp[(i - 7) & 7])];
                    }

                    Copy(m, temp, 8);
                }

                for (int i = 0; i < 8; i++)
                    //m_hash[i] ^= temp[i] ^ data[i];
                    m_hash[i] ^= m[i] ^ data[i];
            }
        }

        private unsafe void Copy(ulong* src, ulong* dst, int len)
        {
            for (int i = 0; i < len; i++) {
                *dst = *src;
                dst ++;
                src ++;
            }
        }
#else
        private void Transform(byte[] input, int offset)
        {
 	        ulong[] k = new ulong[8];
            ulong[] m = new ulong[8];

            ulong[] temp = new ulong[8];
            ulong[] data = new ulong[8];

            //ConvertBytesToULongsSwapOrder(input, offset, BlockSizeBytes, data);
            for (int i = 0; i < data.Length; i++) {
                data[i] = input.BigEndianToUInt64(offset + (i * sizeof(ulong)));
            }

            for (int i = 0; i < 8; i++)
            {
                k[i] = m_hash[i];
                temp[i] = data[i] ^ k[i];
            }

            for (int round = 1; round <= ROUNDS; round++)
            {
                for (int i = 0; i < 8; i++)
                {
                    m[i] = 0;
                    m[i] ^= s_C0[(byte)(k[(i - 0) & 7] >> 56)];
                    m[i] ^= s_C1[(byte)(k[(i - 1) & 7] >> 48)];
                    m[i] ^= s_C2[(byte)(k[(i - 2) & 7] >> 40)];
                    m[i] ^= s_C3[(byte)(k[(i - 3) & 7] >> 32)];
                    m[i] ^= s_C4[(byte)(k[(i - 4) & 7] >> 24)];
                    m[i] ^= s_C5[(byte)(k[(i - 5) & 7] >> 16)];
                    m[i] ^= s_C6[(byte)(k[(i - 6) & 7] >> 8)];
                    m[i] ^= s_C7[(byte)(k[(i - 7) & 7])];
                }

                Array.Copy(m, 0, k, 0, k.Length);

                k[0] ^= s_rc[round];

                for (int i = 0; i < 8; i++)
                {
                    m[i] = k[i];

                    m[i] ^= s_C0[(byte)(temp[(i - 0) & 7] >> 56)];
                    m[i] ^= s_C1[(byte)(temp[(i - 1) & 7] >> 48)];
                    m[i] ^= s_C2[(byte)(temp[(i - 2) & 7] >> 40)];
                    m[i] ^= s_C3[(byte)(temp[(i - 3) & 7] >> 32)];
                    m[i] ^= s_C4[(byte)(temp[(i - 4) & 7] >> 24)];
                    m[i] ^= s_C5[(byte)(temp[(i - 5) & 7] >> 16)];
                    m[i] ^= s_C6[(byte)(temp[(i - 6) & 7] >> 8)];
                    m[i] ^= s_C7[(byte)(temp[(i - 7) & 7])];
                }

                //Array.Copy(m, 0, temp, 0, temp.Length);
            }

            for (int i = 0; i < 8; i++)
                //m_hash[i] ^= temp[i] ^ data[i];
                m_hash[i] ^= m[i] ^ data[i];
        }
#endif

        //private static void ConvertULongToBytesSwapOrder(ulong a_in, byte[] a_out, int a_index)
        //{
        //    Debug.Assert(a_index + 8 <= a_out.Length);

        //    a_out[a_index++] = (byte)(a_in >> 56);
        //    a_out[a_index++] = (byte)(a_in >> 48);
        //    a_out[a_index++] = (byte)(a_in >> 40);
        //    a_out[a_index++] = (byte)(a_in >> 32);
        //    a_out[a_index++] = (byte)(a_in >> 24);
        //    a_out[a_index++] = (byte)(a_in >> 16);
        //    a_out[a_index++] = (byte)(a_in >> 8);
        //    a_out[a_index++] = (byte)a_in;
        //}

        //private static byte[] ConvertULongsToBytesSwapOrder(ulong[] a_in, int a_index = 0, int a_length = -1)
        //{
        //    if (a_length == -1)
        //        a_length = a_in.Length;

        //    byte[] result = new byte[a_length * 8];

        //    for (int j = 0; a_length > 0; a_length--, a_index++) {
        //        result[j++] = (byte)(a_in[a_index] >> 56);
        //        result[j++] = (byte)(a_in[a_index] >> 48);
        //        result[j++] = (byte)(a_in[a_index] >> 40);
        //        result[j++] = (byte)(a_in[a_index] >> 32);
        //        result[j++] = (byte)(a_in[a_index] >> 24);
        //        result[j++] = (byte)(a_in[a_index] >> 16);
        //        result[j++] = (byte)(a_in[a_index] >> 8);
        //        result[j++] = (byte)a_in[a_index];
        //    }

        //    return result;
        //}

        public int DoFinal(byte[] output, int outOff)
        {
            ulong bits = (ulong)(m_processed_bytes * sizeof(ulong));

            int padindex = (_bufferFilled > 31) ? (120 - _bufferFilled) : (56 - _bufferFilled);

            byte[] pad = new byte[padindex + sizeof(ulong)];

            pad[0] = 0x80;

            //ConvertULongToBytesSwapOrder(bits, pad, padindex);
            bits.ToBigEndian(pad, padindex);
            padindex += sizeof(ulong);

            BlockUpdate(pad, 0, padindex);

            //ConvertULongsToBytesSwapOrder(m_hash);
            for (int i = 0; i < m_hash.Length; i++) {
                m_hash[i].ToBigEndian(output, outOff);
                outOff += sizeof(ulong);
            }

            return DigestSize;
        }

        public void Reset()
        {
            _buffer.SecureWipe();
            _bufferFilled = 0;
        }
    }
}
