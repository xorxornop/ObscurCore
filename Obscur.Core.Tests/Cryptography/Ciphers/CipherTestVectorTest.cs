//
//  Copyright 2014  Matthew Ducker
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
using System.Collections.Generic;
using System.IO;

using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

using NUnit.Framework;

namespace ObscurCore.Tests.Cryptography
{
	public abstract class CipherTestVectorTest
	{
		public List<TestCase> VectorTestCases { get; private set; }

		public class TestCase
		{
			private string name;
			private byte[] key;
			private byte[] iv;
			private byte[] plaintext;
			private byte[] ciphertext;

			public TestCase(string name, string key, string iv, string plaintext, string ciphertext)
			{
				this.name = name;
				this.key = Hex.Decode(key);
				this.iv = Hex.Decode(iv);
				this.plaintext = Hex.Decode(plaintext);
				this.ciphertext = Hex.Decode(ciphertext);
			}

			public string Name
			{
				get { return name; }
			}

			public byte[] Key
			{
				get { return key; }
			}

			public byte[] Iv
			{
				get { return iv; }
			}

			public byte[] Plaintext
			{
				get { return plaintext; }
			}

			public byte[] Ciphertext
			{
				get { return ciphertext; }
			}
		}


		public void RunVectorTests() {
			for (int i = 0; i < VectorTestCases.Count; i++) {
				VectorTestImplementation (i, VectorTestCases [i]);
			}
			Assert.Pass (VectorTestCases.Count + " tests ran successfully.");
		}

		public void RunVectorTest (int number, TestCase testCase) {
			VectorTestImplementation (number, testCase);
		}

		protected abstract SymmetricCipherConfiguration GetCipherConfigurationForVectorTest (TestCase testCase);

		protected void VectorTestImplementation(int number, TestCase testCase) {
			byte[] plaintext = testCase.Plaintext;

			var config = GetCipherConfigurationForVectorTest (testCase);

			var msCiphertext = new MemoryStream ();

			using (var cs = new SymmetricCryptoStream(msCiphertext, true, config, testCase.Key, false)) {
				cs.Write (testCase.Plaintext, 0, testCase.Plaintext.Length);
			}

			byte[] ciphertext = msCiphertext.ToArray ();

			if (!testCase.Ciphertext.AreEqual(ciphertext)) {
				Assert.Fail ("Test " + number + " failed!");
			}
		}
	}

	/// <summary>
	/// Class to decode and encode Hex.
	/// </summary>
	public sealed class Hex
	{
		private static readonly IEncoder encoder = new HexEncoder();

		private Hex()
		{
		}

		public static string ToHexString(
			byte[] data)
		{
			return ToHexString(data, 0, data.Length);
		}

		public static string ToHexString(
			byte[]        data,
			int                off,
			int                length)
		{
			byte[] hex = Encode(data, off, length);
			return FromAsciiByteArray(hex);
		}

		public static string FromAsciiByteArray(
			byte[] bytes)
		{
			return System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
		}

		/*				*
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
		public static byte[] Encode(
			byte[] data)
		{
			return Encode(data, 0, data.Length);
		}

		/*				*
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
		public static byte[] Encode(
			byte[]        data,
			int                off,
			int                length)
		{
			MemoryStream bOut = new MemoryStream(length * 2);

			encoder.Encode(data, off, length, bOut);

			return bOut.ToArray();
		}

		/*				*
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
		public static int Encode(
			byte[]        data,
			Stream        outStream)
		{
			return encoder.Encode(data, 0, data.Length, outStream);
		}

		/*				*
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
		public static int Encode(
			byte[]        data,
			int                off,
			int                length,
			Stream        outStream)
		{
			return encoder.Encode(data, off, length, outStream);
		}

		/*				*
         * decode the Hex encoded input data. It is assumed the input data is valid.
         *
         * @return a byte array representing the decoded data.
         */
		public static byte[] Decode(
			byte[] data)
		{
			MemoryStream bOut = new MemoryStream((data.Length + 1) / 2);

			encoder.Decode(data, 0, data.Length, bOut);

			return bOut.ToArray();
		}

		/*				*
         * decode the Hex encoded string data - whitespace will be ignored.
         *
         * @return a byte array representing the decoded data.
         */
		public static byte[] Decode(
			string data)
		{
			MemoryStream bOut = new MemoryStream((data.Length + 1) / 2);

			encoder.DecodeString(data, bOut);

			return bOut.ToArray();
		}

		/*				*
         * decode the Hex encoded string data writing it to the given output stream,
         * whitespace characters will be ignored.
         *
         * @return the number of bytes produced.
         */
		public static int Decode(
			string        data,
			Stream        outStream)
		{
			return encoder.DecodeString(data, outStream);
		}
	}

	public class HexEncoder
		: IEncoder
	{
		private static readonly byte[] encodingTable =
		{
			(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
			(byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
		};

		private static readonly byte[] decodingTable = ConstructDecodingTable(encodingTable);

		private static byte[] ConstructDecodingTable(byte[] et)
		{
			byte[] dt = new byte[128];
			for (int i = 0; i < et.Length; i++)
			{
				dt[et[i]] = (byte)i;
			}

			dt['A'] = dt['a'];
			dt['B'] = dt['b'];
			dt['C'] = dt['c'];
			dt['D'] = dt['d'];
			dt['E'] = dt['e'];
			dt['F'] = dt['f'];

			return dt;
		}

		/*				*
                * encode the input data producing a Hex output stream.
                *
                * @return the number of bytes produced.
                */
		public int Encode(
			byte[]        data,
			int                off,
			int                length,
			Stream        outStream)
		{
			for (int i = off; i < (off + length); i++)
			{
				int v = data[i];

				outStream.WriteByte(encodingTable[v >> 4]);
				outStream.WriteByte(encodingTable[v & 0xf]);
			}

			return length * 2;
		}

		private static bool Ignore(char c)
		{
			return c == '\n' || c =='\r' || c == '\t' || c == ' ';
		}

		/*				*
                * decode the Hex encoded byte data writing it to the given output stream,
                * whitespace characters will be ignored.
                *
                * @return the number of bytes produced.
                */
		public int Decode(
			byte[]        data,
			int                off,
			int                length,
			Stream        outStream)
		{
			byte b1, b2;
			int outLen = 0;
			int end = off + length;

			while (end > off)
			{
				if (!Ignore((char)data[end - 1]))
				{
					break;
				}

				end--;
			}

			int i = off;
			while (i < end)
			{
				while (i < end && Ignore((char)data[i]))
				{
					i++;
				}

				b1 = decodingTable[data[i++]];

				while (i < end && Ignore((char)data[i]))
				{
					i++;
				}

				b2 = decodingTable[data[i++]];

				outStream.WriteByte((byte)((b1 << 4) | b2));

				outLen++;
			}

			return outLen;
		}

		/*				*
                * decode the Hex encoded string data writing it to the given output stream,
                * whitespace characters will be ignored.
                *
                * @return the number of bytes produced.
                */
		public int DecodeString(
			string        data,
			Stream        outStream)
		{
			byte    b1, b2;
			int     length = 0;

			int     end = data.Length;

			while (end > 0)
			{
				if (!Ignore(data[end - 1]))
				{
					break;
				}

				end--;
			}

			int i = 0;
			while (i < end)
			{
				while (i < end && Ignore(data[i]))
				{
					i++;
				}

				b1 = decodingTable[data[i++]];

				while (i < end && Ignore(data[i]))
				{
					i++;
				}

				b2 = decodingTable[data[i++]];

				outStream.WriteByte((byte)((b1 << 4) | b2));

				length++;
			}

			return length;
		}
	}

	public interface IEncoder
	{
		int Encode(byte[] data, int off, int length, Stream outStream);

		int Decode(byte[] data, int off, int length, Stream outStream);

		int DecodeString(string data, Stream outStream);
	}
}

