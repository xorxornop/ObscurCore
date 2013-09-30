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
using System.Text;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.DTO;

namespace ObscurCore.Extensions
{
    namespace DTO
    {
            public static class PayloadItemExtensions
            {
                public static DecoratingStream BindTransformStream(this PayloadItem item, bool writing, Stream binding = null) {
                    DecoratingStream stream = null;

                    if (item.Encryption.Key == null || item.Encryption.Key.Length == 0) {
                        throw new ItemKeyMissingException(item);
                    }

                    if (item.Encryption != null) stream = new SymmetricCryptoStream(binding, writing, item.Encryption, null, true);
                    //if (item.Compression != null) stream = new CompressoStream(stream ?? binding, writing, true, item.Compression);

                    return stream;
                }

                public static string GetFileName (this PayloadItem item, bool withExtension = true, bool defaultExtension = true) {
                    var pathSegments = item.RelativePath.Split(new char[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
                    var segment = pathSegments[pathSegments.Length - 1];
                    var extensionStartIndex = segment.LastIndexOf('.');
                    segment = withExtension ? segment : segment.Substring(0, segment.LastIndexOf('.') - 1);

                    switch (item.Type) {
                        case PayloadItemTypes.Binary:
                            return (defaultExtension && withExtension && extensionStartIndex == -1) ? segment + ".bin" : segment;
                        case PayloadItemTypes.UTF32:
                        case PayloadItemTypes.UTF8:
                            return (defaultExtension && withExtension && extensionStartIndex == -1) ? segment + ".txt" : segment;
                        default:
                            throw new NotSupportedException("Item is a key agreement. It is not intended to be emitted as a file.");
                    }

                }

                public static string GetItemName (this PayloadItem item) {
                    return GetFileName(item, false);
                }
            }
        }

        namespace EllipticCurve
        {
            public static class ECKeyConfigurationExtensions
            {
                public static ECPublicKeyParameters DecodeToPublicKey(this ECKeyConfiguration config) {
                    if (!config.CurveProviderName.Equals ("Brainpool"))
                        throw new InvalidDataException ("Curve providers other than \"Brainpool\" are not currently supported.");

                    ECPublicKeyParameters publicKey;
                    try {
                        var domain = Source.GetECDomainParameters(config.CurveName);
                        ECPoint point;
                        ECKeyUtility.Read (config.EncodedKey, domain, out point);
                        publicKey = new ECPublicKeyParameters("ECDHC", point, domain);
                    } catch (NotSupportedException) {
                        throw new NotSupportedException ("EC curve specified for UM1 agreement is not in the collection of curves of the provider.");
                    } catch (Exception) {
                        throw new InvalidDataException("Unspecified error occured in decoding EC key.");
                    }
                    return publicKey;
                }

                public static ECPrivateKeyParameters DecodeToPrivateKey(this ECKeyConfiguration config) {
                    if (!config.CurveProviderName.Equals ("Brainpool"))
                        throw new InvalidDataException ("Curve providers other than \"Brainpool\" are not currently supported.");

                    ECPrivateKeyParameters privateKey;
                    try {
                        var domain = Source.GetECDomainParameters(config.CurveName);
                        ECPoint point;
                        ECKeyUtility.Read (config.EncodedKey, domain, out point);
                        privateKey = new ECPrivateKeyParameters("ECDHC", new BigInteger(config.EncodedKey), domain);

                    } catch (NotSupportedException) {
                        throw new NotSupportedException ("EC curve specified for UM1 agreement is not in the collection of curves of the provider.");
                    } catch (Exception) {
                        throw new InvalidDataException("Unspecified error occured in decoding EC key.");
                    }
                    return privateKey;
                }

                public static void EncodePublicKey(this ECKeyConfiguration config, string curveProvider, string curveName, ECPoint key) {
                    if (!curveProvider.Equals ("Brainpool"))
                        throw new ArgumentException ("Curve providers other than \"Brainpool\" are not currently supported.");
                    config.CurveProviderName = curveProvider;
                    BrainpoolECFpCurves curveEnum;
                    if(!Enum.TryParse(curveName, out curveEnum)) 
                        throw new NotSupportedException ("EC curve specified for UM1 agreement is not in the collection of curves of the provider.");
                    config.CurveName = curveName;
                    config.EncodedKey = ECKeyUtility.Write (key);
                }

                public static void EncodePrivateKey(this ECKeyConfiguration config, string curveProvider, string curveName, BigInteger key) {
                    if (!curveProvider.Equals ("Brainpool"))
                        throw new ArgumentException ("Curve providers other than \"Brainpool\" are not currently supported.");
                    config.CurveProviderName = curveProvider;
                    BrainpoolECFpCurves curveEnum;
                    if(!Enum.TryParse(curveName, out curveEnum)) 
                        throw new NotSupportedException ("EC curve specified for UM1 agreement is not in the collection of curves of the provider.");
                    config.CurveName = curveName;
                    config.EncodedKey = key.ToByteArray ();
                }
            }
        }

        namespace Generic
        {
            public static class GenericExtensionMethods
            {
                public static bool IsBetween<T>(this T value, T low, T high) where T : IComparable<T> {
                    return value.CompareTo(low) >= 0 && value.CompareTo(high) <= 0;
                }
            }
        }

#if INCLUDE_UNSAFE
    namespace Binary
    {
        public static class BinaryExtensions
        {
            private const int bitsinbyte = 8;
            private static readonly int paralleldegree;
            private static readonly int uintsize;
            private static readonly int bitsinuint;

            static BinaryExtensions() {
                paralleldegree = Environment.ProcessorCount;
                uintsize = sizeof(uint) / sizeof(byte); // really paranoid, uh ?
                bitsinuint = uintsize * bitsinbyte;
            }

            public static byte[] ParallelXOR (this byte[] ba, byte[] bt, int? partitionsArg = null) {
                var partitions = partitionsArg ?? paralleldegree;
                
                var lenbig = Math.Max(ba.Length, bt.Length);
                var lensmall = Math.Min(ba.Length, bt.Length);
                var result = new byte[lenbig];
                var ipar = 0;
                var o = new object();
                Action paction = () => {
                        int actidx;
                        lock (o) {
                            actidx = ipar++;
                        }
                        unsafe {
                            fixed (byte* ptres = result, ptba = ba, ptbt = bt) {
                                uint* pr = ((uint*) ptres) + actidx;
                                uint* pa = ((uint*) ptba) + actidx;
                                uint* pt = ((uint*) ptbt) + actidx;
                                while (pr < ptres + lensmall) {
                                    *pr = (*pt ^ *pa);
                                    pr += partitions; pa += partitions; pt += partitions;
                                }
                                uint* pl = ba.Length > bt.Length ? pa : pt;
                                while (pr < ptres + lenbig) {
                                    *pr = *pl;
                                    pr += partitions; pl += partitions;
                                }
                            }
                        }
                    };
                var actions = new Action[partitions];
                for (var i = 0; i < partitions; i++) {
                    actions[i] = paction;
                }
                Parallel.Invoke(actions);

                return result;
            }

            public static byte[] ParallelAnd (this byte[] ba, byte[] bt) {
                int lenbig = Math.Max(ba.Length, bt.Length);
                int lensmall = Math.Min(ba.Length, bt.Length);
                byte[] result = new byte[lenbig];
                int ipar = 0;
                object o = new object();
                System.Action paction = delegate() {
                    int actidx;
                    lock (o) {
                        actidx = ipar++;
                    }
                    unsafe {
                        fixed (byte* ptres = result, ptba = ba, ptbt = bt) {
                            uint* pr = (uint*) ptres;
                            uint* pa = (uint*) ptba;
                            uint* pt = (uint*) ptbt;
                            pr += actidx; pa += actidx; pt += actidx;
                            while (pr < ptres + lensmall) {
                                *pr = (*pt & *pa);
                                pr += paralleldegree; pa += paralleldegree; pt += paralleldegree;
                            }
                        }
                    }
                };
                System.Action[] actions = new Action[paralleldegree];
                for (int i = 0; i < paralleldegree; i++) {
                    actions[i] = paction;
                }
                Parallel.Invoke(actions);
                return result;
            }

            public static byte[] ParallelOr (this byte[] ba, byte[] bt) {
                int lenbig = Math.Max(ba.Length, bt.Length);
                int lensmall = Math.Min(ba.Length, bt.Length);
                byte[] result = new byte[lenbig];
                int ipar = 0;
                object o = new object();
                System.Action paction = delegate() {
                        int actidx;
                        lock (o) {
                            actidx = ipar++;
                        }
                        unsafe {
                            fixed (byte* ptres = result, ptba = ba, ptbt = bt) {
                                uint* pr = (uint*) ptres;
                                uint* pa = (uint*) ptba;
                                uint* pt = (uint*) ptbt;
                                pr += actidx; pa += actidx; pt += actidx;
                                while (pr < ptres + lensmall) {
                                    *pr = (*pt | *pa);
                                    pr += paralleldegree; pa += paralleldegree; pt += paralleldegree;
                                }
                                uint* pl = ba.Length > bt.Length ? pa : pt;
                                while (pr < ptres + lenbig) {
                                    *pr = *pl;
                                    pr += paralleldegree; pl += paralleldegree;
                                }
                            }
                        }
                    };
                System.Action[] actions = new Action[paralleldegree];
                for (int i = 0; i < paralleldegree; i++) {
                    actions[i] = paction;
                }
                Parallel.Invoke(actions);

                return result;
            }

            public static byte[] ParallelLeftShift (this byte[] ba, int bits, int? partitionsArg = null) {
                var ipar = 0;
                var o = new object();

                var len = ba.Length;
                if (bits >= len * bitsinbyte) return new byte[len];
                var shiftbits = bits % bitsinuint;
                var shiftuints = bits / bitsinuint;
                var result = new byte[len];

                if (len > 1) {
                    // first uint is shifted without carry from previous byte (previous byte does not exist)
                    unsafe {
                        fixed (byte* fpba = ba, fpres = result) {
                            uint* pres = (uint*) fpres + shiftuints;
                            uint* pba = (uint*) fpba;
                            *pres = *pba << shiftbits;
                        }
                    }
                    Action paction = () => {
                            int actidx;
                            lock (o) actidx = ipar++;
                            unsafe {
                                fixed (byte* fpba = ba, fpres = result) {
                                    // pointer to results; shift the bytes in the result
                                    // (i.e. move left the pointer to the result)
                                    uint* pres = (uint*) fpres + shiftuints + actidx + 1;
                                    // pointer to original data, second byte
                                    uint* pba1 = (uint*) fpba + actidx + 1;
                                    if (shiftbits == 0) {
                                        while (pres < fpres + len) {
                                            *pres = *pba1;
                                            pres += paralleldegree; pba1 += paralleldegree;
                                        }
                                    } else {
                                        // pointer to original data, first byte
                                        uint* pba2 = (uint*) fpba + actidx;
                                        while (pres < fpres + len) {
                                            *pres = *pba2 >> (bitsinuint - shiftbits) | *pba1 << shiftbits;
                                            pres += paralleldegree; pba1 += paralleldegree; pba2 += paralleldegree;
                                        }
                                    }
                                }
                            };

                        };
                    var actions = new Action[paralleldegree];
                    for (int i = 0; i < paralleldegree; i++) {
                        actions[i] = paction;
                    }
                    Parallel.Invoke(actions);
                }

                return result;
            }

            public static byte[] ParallelRightShift (this byte[] ba, int bits, int? partitionsArg = null) {
            int ipar = 0;
            object o = new object();
            int len = ba.Length;
            if (bits >= len * bitsinbyte) return new byte[len];
            int ulen = len / uintsize + 1 - (uintsize - (len % uintsize)) / uintsize;
            int shiftbits = bits % bitsinuint;
            int shiftuints = bits / bitsinuint;
            byte[] result = new byte[len];

            if (len > 1)
                {
                unsafe {
                    fixed (byte* fpba = ba, fpres = result) {
                        uint* pres = (uint*)fpres + ulen - shiftuints - 1;
                        uint* pba = (uint*)fpba + ulen - 1;
                        *pres = *pba >> shiftbits;
                    }
                }
                Action paction = () => {
                    int actidx;
                    lock (o) actidx = ipar++;
                    unsafe {
                        fixed (byte* fpba = ba, fpres = result) {
                            // pointer to results; shift the bytes in the result
                            // (i.e. move left the pointer to the result)
                            uint* pres = (uint*) fpres + actidx;
                            // pointer to original data, first useful byte
                            uint* pba1 = (uint*) fpba + shiftuints + actidx;
                            if (shiftbits == 0) {
                                while (pres < ((uint*) fpres) + ulen - shiftuints - 1) {
                                    *pres = *pba1;
                                    // increment pointers to next position
                                    pres += paralleldegree;
                                    pba1 += paralleldegree;
                                }
                            } else {
                                // pointer to original data, second useful byte
                                uint* pba2 = (uint*) fpba + shiftuints + actidx + 1;
                                while (pres < ((uint*) fpres) + ulen - shiftuints - 1)
                                {
                                    // Core shift operation
                                    *pres = (*pba1 >> shiftbits | *pba2 << (bitsinuint - shiftbits));
                                    // increment pointers to next position
                                    pres += paralleldegree;
                                    pba1 += paralleldegree;
                                    pba2 += paralleldegree;
                                }
                            }
                        }
                    }
                };
                var actions = new Action[paralleldegree];
                for (var i = 0; i < paralleldegree; i++) {
                    actions[i] = paction;
                }
                Parallel.Invoke(actions);
                }
            return result;
            }
        }
    }
#endif

        namespace Enumerations
        {
            public static class EnumExtensions
            {
                public static T FromString<T>(this T type, string value) where T : struct, IConvertible {
                    if (!typeof (T).IsEnum) throw new InvalidOperationException("T must be an enumerated type.");
                    T outputType;
                    try {
                        outputType = (T) System.Enum.Parse(typeof (T), value);
                    } catch (ArgumentException) {
                        throw new ArgumentException("Enumeration member is unknown / invalid.");
                    }
                    return outputType;
                }


                /// <summary>
                /// Reads an enumeration value encoded as a string.
                /// </summary>
                /// <typeparam name='T'>
                /// Must be an enumeration type.
                /// </typeparam>
                public static void ToEnum<T>(this string stringValue, out T value) where T : struct, IConvertible {
                    if (!typeof (T).IsEnum) throw new InvalidOperationException("T must be an enumerated type.");
                    try {
                        value = (T) System.Enum.Parse(typeof (T), stringValue);
                    } catch (ArgumentException) {
                        throw new ArgumentException("Enumeration member is unknown / invalid.");
                    }
                }

                public static T ToEnum<T>(this string stringValue, bool ignoreCase = false) where T : struct, IConvertible {
                    if (!typeof (T).IsEnum) throw new InvalidOperationException("T must be an enumerated type.");
                    T value;
                    try {
                        value = (T) System.Enum.Parse(typeof (T), stringValue, ignoreCase);
                    } catch (ArgumentException) {
                        throw new ArgumentException("Enumeration member is unknown / invalid.");
                    }
                    return value;
                }
            }
        }

        namespace Streams
        {
            public static class StreamExtensions
            {
                public static void WritePrimitive(this Stream stream, bool value) {
                    stream.WriteByte(value ? (byte) 1 : (byte) 0);
                }

                public static void ReadPrimitive(this Stream stream, out bool value) {
                    var b = stream.ReadByte();
                    value = b != 0;
                }

                public static void WritePrimitive(this Stream stream, byte value) {
                    stream.WriteByte(value);
                }

                public static void ReadPrimitive(this Stream stream, out byte value) {
                    value = (byte) stream.ReadByte();
                }

                public static void WritePrimitive(this Stream stream, sbyte value) {
                    stream.WriteByte((byte) value);
                }

                public static void ReadPrimitive(this Stream stream, out sbyte value) {
                    value = (sbyte) stream.ReadByte();
                }

                public static void WritePrimitive(this Stream stream, char value) {
                    WriteVarint32(stream, value);
                }

                public static void ReadPrimitive(this Stream stream, out char value) {
                    value = (char) ReadVarint32(stream);
                }

                public static void WritePrimitive(this Stream stream, ushort value) {
                    WriteVarint32(stream, value);
                }

                public static void ReadPrimitive(this Stream stream, out ushort value) {
                    value = (ushort) ReadVarint32(stream);
                }

                public static void WritePrimitive(this Stream stream, short value) {
                    WriteVarint32(stream, EncodeZigZag32(value));
                }

                public static void ReadPrimitive(this Stream stream, out short value) {
                    value = (short) DecodeZigZag32(ReadVarint32(stream));
                }

                public static void WritePrimitive(this Stream stream, uint value) {
                    WriteVarint32(stream, value);
                }

                public static void ReadPrimitive(this Stream stream, out uint value) {
                    value = ReadVarint32(stream);
                }

                public static void WritePrimitive(this Stream stream, int value) {
                    WriteVarint32(stream, EncodeZigZag32(value));
                }

                public static void ReadPrimitive(this Stream stream, out int value) {
                    value = DecodeZigZag32(ReadVarint32(stream));
                }

                public static void WritePrimitive(this Stream stream, ulong value) {
                    WriteVarint64(stream, value);
                }

                public static void ReadPrimitive(this Stream stream, out ulong value) {
                    value = ReadVarint64(stream);
                }

                public static void WritePrimitive(this Stream stream, long value) {
                    WriteVarint64(stream, EncodeZigZag64(value));
                }

                public static void ReadPrimitive(this Stream stream, out long value) {
                    value = DecodeZigZag64(ReadVarint64(stream));
                }

#if INCLUDE_UNSAFE
            public static unsafe void WritePrimitive(this Stream stream, float value)
			{
				uint v = *(uint*)(&value);
				WriteVarint32(stream, v);
			}
			
			public static unsafe void ReadPrimitive(this Stream stream, out float value)
			{
				uint v = ReadVarint32(stream);
				value = *(float*)(&v);
			}
			
			public static unsafe void WritePrimitive(this Stream stream, double value)
			{
				ulong v = *(ulong*)(&value);
				WriteVarint64(stream, v);
			}
			
			public static unsafe void ReadPrimitive(this Stream stream, out double value)
			{
				ulong v = ReadVarint64(stream);
				value = *(double*)(&v);
			}
#endif

                public static void WritePrimitive(this Stream stream, DateTime value) {
                    var v = value.ToBinary();
                    WritePrimitive(stream, v);
                }

                public static void ReadPrimitive(this Stream stream, out DateTime value) {
                    long v;
                    ReadPrimitive(stream, out v);
                    value = DateTime.FromBinary(v);
                }

                public static void WritePrimitive(this Stream stream, string value) {
                    if (value == null) {
                        WritePrimitive(stream, (uint) 0);
                        return;
                    }

                    var encoding = new UTF8Encoding(false, true);

                    var len = encoding.GetByteCount(value);

                    WritePrimitive(stream, (uint) len + 1);

                    var buf = new byte[len];

                    encoding.GetBytes(value, 0, value.Length, buf, 0);

                    stream.Write(buf, 0, len);
                }

                public static void ReadPrimitive(this Stream stream, out string value) {
                    uint len;
                    ReadPrimitive(stream, out len);

                    switch (len) {
                        case 0:
                            value = null;
                            return;
                        case 1:
                            value = string.Empty;
                            return;
                    }

                    len -= 1;

                    var encoding = new UTF8Encoding(false, true);

                    var buf = new byte[len];

                    var l = 0;

                    while (l < len) {
                        int r = stream.Read(buf, l, (int) len - l);
                        if (r == 0)
                            throw new EndOfStreamException();
                        l += r;
                    }

                    value = encoding.GetString(buf);
                }



                public static void WritePrimitive(this Stream stream, byte[] value) {
                    if (value == null) {
                        WritePrimitive(stream, (uint) 0);
                        return;
                    }

                    WritePrimitive(stream, (uint) value.Length + 1);
                    stream.Write(value, 0, value.Length);
                }

                public static void WritePrimitive(this Stream stream, byte[] value, int offset, int count) {
                    if (value == null) {
                        WritePrimitive(stream, (uint) 0);
                        return;
                    }

                    WritePrimitive(stream, (uint) count + 1);
                    stream.Write(value, offset, count);
                }

                public static void WritePrimitiveMeta(this Stream stream, byte[] value, bool negative) {
                    stream.WritePrimitiveMeta(value, 0, value.Length, negative);
                }

                /// <summary>
                /// Writes a length-encoded byte array with additional boolean property stored as integer sign.
                /// </summary>
                /// <param name="stream">Stream to write to.</param>
                /// <param name="value">Source byte array.</param>
                /// <param name="offset">Offset at which to start writing bytes from the source array.</param>
                /// <param name="count">Number of bytes to be written.</param>
                /// <param name="negative">If set to <c>true</c> length-specifying integer will be stored with negative sign.</param>
                public static void WritePrimitiveMeta(this Stream stream, byte[] value, int offset, int count,
                                                      bool negative) {
                    if (value == null) {
                        WritePrimitive(stream, 0);
                        return;
                    }

                    WritePrimitive(stream, negative ? -(count + 1) : count + 1);
                    stream.Write(value, offset, count);
                }

                private static readonly byte[] EmptyByteArray = new byte[0];

                public static void ReadPrimitive(this Stream stream, out byte[] value) {
                    uint len;
                    ReadPrimitive(stream, out len);

                    switch (len) {
                        case 0:
                            value = null;
                            return;
                        case 1:
                            value = EmptyByteArray;
                            return;
                    }

                    len -= 1;

                    value = new byte[len];
                    var l = 0;

                    while (l < len) {
                        var r = stream.Read(value, l, (int) len - l);
                        if (r == 0) throw new EndOfStreamException();
                        l += r;
                    }
                }

                /// <summary>
                /// Reads a length-encoded byte array with additional boolean property stored as integer sign.
                /// </summary>
                /// <param name="stream">Stream to be read from.</param>
                /// <param name="value">Output byte array.</param>
                /// <param name="negative">Stored boolean state. Will be <c>true</c> if stored integer has negative sign.</param>
                public static void ReadPrimitiveMeta(this Stream stream, out byte[] value, out bool negative) {
                    int len;
                    ReadPrimitive(stream, out len);

                    negative = Math.Sign(len) < 0;
                    len = Math.Abs(len);

                    switch (len) {
                        case 0:
                            value = null;
                            return;
                        case 1:
                            value = EmptyByteArray;
                            return;
                    }

                    len -= 1;

                    value = new byte[len];
                    var l = 0;

                    while (l < len) {
                        var r = stream.Read(value, l, len - l);
                        if (r == 0) throw new EndOfStreamException();
                        l += r;
                    }
                }

                /// <summary>
                /// Reads an enumeration value from a stream that was encoded as a string.
                /// </summary>
                /// <typeparam name='T'>
                /// Must be an enumeration type.
                /// </typeparam>
                public static void ReadPrimitive<T>(this Stream stream, out T value) where T : struct, IConvertible {

                    if (!typeof (T).IsEnum) throw new InvalidOperationException("T must be an enumerated type.");
                    try {
                        string stringValue;
                        ReadPrimitive(stream, out stringValue);
                        value = (T) Enum.Parse(typeof (T), stringValue);
                    } catch (ArgumentException) {
                        throw new ArgumentException("Enumeration member is unknown or otherwise invalid.");
                    }
                }

                /// <summary>
                /// Writes an enumeration value into a stream, encoded as a string .
                /// </summary>
                /// <typeparam name='T'>
                /// Must be an enumeration type.
                /// </typeparam>
                public static void WritePrimitive<T>(this Stream stream, T value) where T : struct, IConvertible {
                    if (!typeof (T).IsEnum) throw new InvalidOperationException("T must be an enumerated type.");

                    WritePrimitive(stream, Enum.GetName(typeof (T), value));
                }

                private static uint EncodeZigZag32(int n) {
                    return (uint) ((n << 1) ^ (n >> 31));
                }

                private static ulong EncodeZigZag64(long n) {
                    return (ulong) ((n << 1) ^ (n >> 63));
                }

                private static int DecodeZigZag32(uint n) {
                    return (int) (n >> 1) ^ -(int) (n & 1);
                }

                private static long DecodeZigZag64(ulong n) {
                    return (long) (n >> 1) ^ -(long) (n & 1);
                }

                private static uint ReadVarint32(Stream stream) {
                    var result = 0;
                    var offset = 0;

                    for (; offset < 32; offset += 7) {
                        int b = stream.ReadByte();
                        if (b == -1)
                            throw new EndOfStreamException();

                        result |= (b & 0x7f) << offset;

                        if ((b & 0x80) == 0)
                            return (uint) result;
                    }

                    throw new InvalidDataException();
                }

                private static void WriteVarint32(Stream stream, uint value) {
                    for (; value >= 0x80u; value >>= 7)
                        stream.WriteByte((byte) (value | 0x80u));

                    stream.WriteByte((byte) value);
                }

                private static ulong ReadVarint64(Stream stream) {
                    long result = 0;
                    var offset = 0;

                    for (; offset < 64; offset += 7) {
                        int b = stream.ReadByte();
                        if (b == -1)
                            throw new EndOfStreamException();

                        result |= ((long) (b & 0x7f)) << offset;

                        if ((b & 0x80) == 0)
                            return (ulong) result;
                    }

                    throw new InvalidDataException();
                }

                private static void WriteVarint64(Stream stream, ulong value) {
                    for (; value >= 0x80u; value >>= 7)
                        stream.WriteByte((byte) (value | 0x80u));

                    stream.WriteByte((byte) value);
                }
            }
        }
    }
