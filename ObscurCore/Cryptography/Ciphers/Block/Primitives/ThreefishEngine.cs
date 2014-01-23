/*
Copyright (c) 2009 Alberto Fajardo

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

using System;

namespace ObscurCore.Cryptography.Ciphers.Block.Primitives
{
	public abstract class ThreefishEngine : IBlockCipher
	{
		protected bool _forEncryption;

		protected const ulong KeyScheduleConst = 0x1BD11BDAA9FC1A22;
		protected const int ExpandedTweakSize = 3;

		protected ulong[] ExpandedKey;
		protected ulong[] ExpandedTweak;

		protected readonly ulong[] _inputBlockBuffer, _outputBlockBuffer;
		protected readonly int _blockSizeBytes, _blockSizeWords; // block size in ulongs, e.g. 256 bit = 4

		protected ThreefishEngine(int words)
		{
			ExpandedTweak = new ulong[ExpandedTweakSize];
			_blockSizeWords = words;
			_blockSizeBytes = words * 8;
			_inputBlockBuffer = new ulong[words];
			_outputBlockBuffer = new ulong[words];
		}

		protected static ulong RotateLeft64(ulong v, int b)
		{
			return (v << b) | (v >> (64 - b));
		}

		protected static ulong RotateRight64(ulong v, int b)
		{
			return (v >> b) | (v << (64 - b));
		}

		protected static void Mix(ref ulong a, ref ulong b, int r)
		{
			a += b;
			b = RotateLeft64(b, r) ^ a;
		}

		protected static void Mix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
		{
			b += k1;
			a += b + k0;
			b = RotateLeft64(b, r) ^ a;
		}

		protected static void UnMix(ref ulong a, ref ulong b, int r)
		{
			b = RotateRight64(b ^ a, r);
			a -= b;
		}

		protected static void UnMix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
		{
			b = RotateRight64(b ^ a, r);
			a -= b + k0;
			b -= k1;
		}

		public void SetTweak(ulong[] tweak)
		{
			ExpandedTweak[0] = tweak[0];
			ExpandedTweak[1] = tweak[1];
			ExpandedTweak[2] = tweak[0] ^ tweak[1];
		}

		public void SetKey(ulong[] key) {
			int i;
			ulong parity = KeyScheduleConst;
			for (i = 0; i < ExpandedKey.Length - 1; i++) {
				ExpandedKey[i] = key[i];
				parity ^= key[i];
			}
			ExpandedKey[i] = parity;
		}

		public static ThreefishEngine CreateCipher(int state_size)
		{
			switch (state_size)
			{
			#if !MONO
			case 256: return new Threefish256SimdEngine();
			#else
			case 256: return new Threefish256Engine();
			#endif
			case 512: return new Threefish512Engine();
//			case 1024: return new Threefish1024();
			default:
				throw new NotSupportedException ();
			}
		}

		abstract public void Encrypt(ulong[] input, ulong[] output);
		abstract public void Decrypt(ulong[] input, ulong[] output);

		#region IBlockCipher implementation

		public void Init (bool encrypting, byte[] key, byte[] iv)
		{
			_forEncryption = encrypting;
			var keyAsUlongs = new ulong[_blockSizeWords];
			Buffer.BlockCopy (key, 0, keyAsUlongs, 0, _blockSizeWords);
			SetKey (keyAsUlongs);
		}

		public int ProcessBlock (byte[] inBuf, int inOff, byte[] outBuf, int outOff) {
			Buffer.BlockCopy (inBuf, inOff, _inputBlockBuffer, 0, _blockSizeBytes);
			if (_forEncryption) {
				Encrypt (_inputBlockBuffer, _outputBlockBuffer);
			} else {
				Decrypt (_inputBlockBuffer, _outputBlockBuffer);
			}
			Buffer.BlockCopy (_outputBlockBuffer, 0, outBuf, outOff, _blockSizeBytes);
			return _blockSizeBytes;
		}

		public void Reset () {
			Array.Clear (_inputBlockBuffer, 0, _blockSizeWords);
			Array.Clear (_outputBlockBuffer, 0, _blockSizeWords);
		}

		public string AlgorithmName {
			get {
				return "Threefish";
			}
		}

		public int BlockSize {
			get {
				return _blockSizeBytes;
			}
		}

		public bool IsPartialBlockOkay {
			get {
				return false;
			}
		}

		#endregion
	}
}

