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

namespace Obscur.Core.Cryptography.KeyDerivation.Primitives
{
	internal static class Utility
	{
		/// <summary>
		/// XORs the two specified byte arrays.
		/// </summary>
		/// <param name="src"></param>
		/// <param name="srcOffset"></param>
		/// <param name="dest"></param>
		/// <param name="destOffset"></param>
		/// <param name="len"></param>
		public static void XorByteArrays(byte[] src, int srcOffset, byte[] dest, int destOffset, int len)
		{
			var max = srcOffset + len;
			while (srcOffset < max)
			{
				dest[destOffset++] ^= src[srcOffset++];
			}
		}

		/// <summary>
		/// XORs the two specified byte arrays.
		/// </summary>
		/// <param name="src"></param>
		/// <param name="srcOffset"></param>
		/// <param name="dest"></param>
		/// <param name="destOffset"></param>
		/// <param name="len"></param>
		public static void XorByteArrays(byte[] src, UInt64 srcOffset, byte[] dest, UInt64 destOffset, UInt64 len)
		{
			var max = srcOffset + len;
			while (srcOffset < max)
			{
				dest[destOffset++] ^= src[srcOffset++];
			}
		}

		/// <summary>
		/// XORs the two specified UInt32 arrays.
		/// </summary>
		/// <param name="src"></param>
		/// <param name="srcOffset"></param>
		/// <param name="dest"></param>
		/// <param name="destOffset"></param>
		/// <param name="len"></param>
		public static void XorUInts(UInt32[] src, UInt64 srcOffset, UInt32[] dest, UInt64 destOffset, UInt64 len)
		{
			var max = srcOffset + len;
			while (srcOffset < max)
			{
				dest[destOffset++] ^= src[srcOffset++];
			}
		}
	}
}

