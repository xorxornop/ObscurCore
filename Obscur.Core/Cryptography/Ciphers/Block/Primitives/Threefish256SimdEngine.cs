/*
 * Copyright (c) 2009 Marcus Griep
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

namespace Obscur.Core.Cryptography.Ciphers.Block.Primitives
{
	/// <summary>
	/// High-performance SIMD-enabled implementation of Threefish cipher with 256-bit block size. 
	/// SIMD operations (currently) only possible using Mono runtime.
	/// </summary>
	internal sealed class Threefish256SimdEngine : ThreefishEngine
	{
		const int CipherSize = 256;
		const int CipherQwords = CipherSize / 64;
		const int ExpandedKeySize = CipherQwords + 1;
		const int Rounds = 72;
		const int SubkeyCount = Rounds / 4 + 1;
		const ShuffleSel XYZWtoZWXY = ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY;

		const int per00 = 14, per01 = 16,
		per10 = 52, per11 = 57,
		per20 = 23, per21 = 40,
		per30 =  5, per31 = 37,
		per40 = 25, per41 = 33,
		per50 = 46, per51 = 12,
		per60 = 58, per61 = 22,
		per70 = 32, per71 = 32;

		public Threefish256SimdEngine() : base(4)
		{
			// Create the expanded key array
			ExpandedKey = new ulong[ExpandedKeySize];
		}

		public override void Encrypt(ulong[] input, ulong[] output)
		{
			// Align the stack to a 16-byte boundary
			ulong z = 0;
			// Cache the block and key schedule
			Vector2ul bZero = new Vector2ul(z),
			bOne = Vector2ul.LoadAligned(ref bZero);
			Vector2ul bA = Vector2ul.LoadAligned(ref bZero),
			bB = Vector2ul.LoadAligned(ref bZero),
			bTempA = Vector2ul.LoadAligned(ref bZero),
			bTempB = Vector2ul.LoadAligned(ref bZero);
			Vector2ul k0 = new Vector2ul(ExpandedKey[0], ExpandedKey[2]),
			k1 = new Vector2ul(ExpandedKey[1], ExpandedKey[3]),
			k2 = new Vector2ul(ExpandedKey[2], ExpandedKey[4]),
			k3 = new Vector2ul(ExpandedKey[3], ExpandedKey[0]),
			k4 = new Vector2ul(ExpandedKey[4], ExpandedKey[1]);
			Vector2ul t0h = new Vector2ul(ExpandedTweak[0], 0),
			t0l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t0h)).Shuffle(XYZWtoZWXY)), 
			t1h = new Vector2ul(ExpandedTweak[1], 0),
			t1l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t1h)).Shuffle(XYZWtoZWXY)),
			t2h = new Vector2ul(ExpandedTweak[2], 0),
			t2l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t2h)).Shuffle(XYZWtoZWXY));
			bOne.Y = 1;
			Vector2ul subkey = Vector2ul.LoadAligned(ref bOne);

			if (input.IsAligned(0))
			{
				Vector2ul.StoreAligned(ref bA, input.GetVectorAligned(0));
				Vector2ul.StoreAligned(ref bTempA, input.GetVectorAligned(2));
			}
			else
			{
				Vector2ul.StoreAligned(ref bA, input.GetVector(0));
				Vector2ul.StoreAligned(ref bTempA, input.GetVector(2));
			}
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bTempA)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bTempA)));

			// Round 1, Subkey 0
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 2
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 3
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 4
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 5, Subkey 1
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 6
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 7
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 8
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 9, Subkey 2
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 10
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 11
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 12
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 13, Subkey 3
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 14
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 15
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 16
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 17, Subkey 4
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 18
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 19
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 20
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 21, Subkey 5
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 22
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 23
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 24
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 25, Subkey 6
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 26
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 27
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 28
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 29, Subkey 7
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 30
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 31
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 32
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 33, Subkey 8
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 34
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 35
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 36
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 37, Subkey 9
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 38
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 39
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 40
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 41, Subkey 10
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 42
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 43
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 44
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 45, Subkey 11
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 46
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 47
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 48
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 49, Subkey 12
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 50
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 51
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 52
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 53, Subkey 13
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 54
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 55
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 56
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 57, Subkey 14
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 58
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 59
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 60
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 61, Subkey 15
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 62
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 63
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 64
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 65, Subkey 16
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per01 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per00 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 66
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per11 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per10 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 67
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per21 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per20 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 68
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per31 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per30 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Round 69, Subkey 17
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per41 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per40 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 70
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per51 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per50 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 71
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per61 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per60 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			// Round 72
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << per71 | Vector2ul.LoadAligned(ref bTempB) >> (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << per70 | Vector2ul.LoadAligned(ref bTempA) >> (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));

			// Subkey 18
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t1l));

			if(output.IsAligned(0))
			{
				output.SetVectorAligned(Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bB)), 0);
				output.SetVectorAligned(Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bB)), 2);
			}
			else
			{
				output.SetVector(Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bB)), 0);
				output.SetVector(Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bB)), 2);
			}
		}

		public override void Decrypt(ulong[] input, ulong[] output)
		{
			// Align the stack to a 16-byte boundary
			ulong z = 0;
			// Cache the block and key schedule
			Vector2ul bZero = new Vector2ul(z),
			bOne = new Vector2ul(0, 1);
			Vector2ul bA = Vector2ul.LoadAligned(ref bZero),
			bB = Vector2ul.LoadAligned(ref bZero),
			bTempA = Vector2ul.LoadAligned(ref bZero),
			bTempB = Vector2ul.LoadAligned(ref bZero);
			Vector2ul k0 = new Vector2ul(ExpandedKey[0], ExpandedKey[2]),
			k1 = new Vector2ul(ExpandedKey[1], ExpandedKey[3]),
			k2 = new Vector2ul(ExpandedKey[2], ExpandedKey[4]),
			k3 = new Vector2ul(ExpandedKey[3], ExpandedKey[0]),
			k4 = new Vector2ul(ExpandedKey[4], ExpandedKey[1]);
			Vector2ul t0h = new Vector2ul(ExpandedTweak[0], 0),
			t0l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t0h)).Shuffle(XYZWtoZWXY)), 
			t1h = new Vector2ul(ExpandedTweak[1], 0),
			t1l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t1h)).Shuffle(XYZWtoZWXY)),
			t2h = new Vector2ul(ExpandedTweak[2], 0),
			t2l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t2h)).Shuffle(XYZWtoZWXY));
			Vector2ul subkey = Vector2ul.LoadAligned(ref bOne) << 4 | Vector2ul.LoadAligned(ref bOne) << 1; // <0, 18>

			if (input.IsAligned(0))
			{
				Vector2ul.StoreAligned(ref bA, input.GetVectorAligned(0));
				Vector2ul.StoreAligned(ref bTempA, input.GetVectorAligned(2));
			}
			else
			{
				Vector2ul.StoreAligned(ref bA, input.GetVector(0));
				Vector2ul.StoreAligned(ref bTempA, input.GetVector(2));
			}
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bTempA)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bTempA)));

			// Subkey 18
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k4) - Vector2ul.LoadAligned(ref t0h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 72
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 71
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 70
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 69, Subkey 17
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t0l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t2h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 68
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 67
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 66
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 65, Subkey 16
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t2l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t1h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 64
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 63
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 62
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 61, Subkey 15
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k0) - Vector2ul.LoadAligned(ref t1l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t0h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 60
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 59
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 58
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 57, Subkey 14
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k4) - Vector2ul.LoadAligned(ref t0l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k0) - Vector2ul.LoadAligned(ref t2h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 56
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 55
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 54
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 53, Subkey 13
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t2l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k4) - Vector2ul.LoadAligned(ref t1h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 52
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 51
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 50
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 49, Subkey 12
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t1l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t0h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 48
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 47
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 46
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 45, Subkey 11
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t0l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t2h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 44
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 43
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 42
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 41, Subkey 10
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k0) - Vector2ul.LoadAligned(ref t2l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t1h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 40
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 39
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 38
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 37, Subkey 9
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k4) - Vector2ul.LoadAligned(ref t1l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k0) - Vector2ul.LoadAligned(ref t0h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 36
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 35
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 34
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 33, Subkey 8
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t0l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k4) - Vector2ul.LoadAligned(ref t2h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 32
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 31
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 30
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 29, Subkey 7
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t2l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t1h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 28
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 27
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 26
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 25, Subkey 6
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t1l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t0h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 24
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 23
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 22
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 21, Subkey 5
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k0) - Vector2ul.LoadAligned(ref t0l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t2h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 20
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 19
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 18
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 17, Subkey 4
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k4) - Vector2ul.LoadAligned(ref t2l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k0) - Vector2ul.LoadAligned(ref t1h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 16
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 15
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 14
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 13, Subkey 3
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t1l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k4) - Vector2ul.LoadAligned(ref t0h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 12
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 11
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 10
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 9, Subkey 2
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t0l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k3) - Vector2ul.LoadAligned(ref t2h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 8
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per71 | Vector2ul.LoadAligned(ref bTempB) << (64 - per71));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per70 | Vector2ul.LoadAligned(ref bTempA) << (64 - per70));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 7
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per61 | Vector2ul.LoadAligned(ref bTempB) << (64 - per61));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per60 | Vector2ul.LoadAligned(ref bTempA) << (64 - per60));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 6
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per51 | Vector2ul.LoadAligned(ref bTempB) << (64 - per51));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per50 | Vector2ul.LoadAligned(ref bTempA) << (64 - per50));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 5, Subkey 1
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per41 | Vector2ul.LoadAligned(ref bTempB) << (64 - per41));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per40 | Vector2ul.LoadAligned(ref bTempA) << (64 - per40));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t2l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k2) - Vector2ul.LoadAligned(ref t1h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			// Round 4
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per31 | Vector2ul.LoadAligned(ref bTempB) << (64 - per31));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per30 | Vector2ul.LoadAligned(ref bTempA) << (64 - per30));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 3
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per21 | Vector2ul.LoadAligned(ref bTempB) << (64 - per21));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per20 | Vector2ul.LoadAligned(ref bTempA) << (64 - per20));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 2
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per11 | Vector2ul.LoadAligned(ref bTempB) << (64 - per11));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per10 | Vector2ul.LoadAligned(ref bTempA) << (64 - per10));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref bB));
			// Round 1, Subkey 0
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(XYZWtoZWXY)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) >> per01 | Vector2ul.LoadAligned(ref bTempB) << (64 - per01));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) >> per00 | Vector2ul.LoadAligned(ref bTempA) << (64 - per00));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) - Vector2ul.LoadAligned(ref k0) - Vector2ul.LoadAligned(ref t1l) - Vector2ul.LoadAligned(ref bB));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) - Vector2ul.LoadAligned(ref k1) - Vector2ul.LoadAligned(ref t0h) - Vector2ul.LoadAligned(ref subkey));
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) - Vector2ul.LoadAligned(ref bOne));

			if(output.IsAligned(0))
			{
				output.SetVectorAligned(Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bB)), 0);
				output.SetVectorAligned(Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bB)), 2);
			}
			else
			{
				output.SetVector(Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bB)), 0);
				output.SetVector(Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bB)), 2);
			}
		}
	}
}