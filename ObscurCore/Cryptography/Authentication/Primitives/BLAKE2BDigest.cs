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
using ObscurCore.Cryptography.Authentication.Primitives.BLAKE2B;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	public class Blake2BDigest : IDigest
	{
		protected Blake2BHasher hasher;
		protected int outputSize;

		public Blake2BDigest (int size, bool bits) : this(size, bits, true)
		{
		}

		protected Blake2BDigest(int size, bool bits, bool init) {
            
            if (bits) size /= 8;

			var config = new Blake2BConfig () {
				Key = null,
				Salt = null,
				Personalization = null,
				OutputSizeInBytes = size,
			};

			outputSize = size;
			if (!init) return;
			hasher = new Blake2BHasher (config);
		}

		#region IDigest implementation

		public int GetDigestSize ()
		{
			return outputSize;
		}

		public int GetByteLength ()
		{
			return 128;
		}

		public void Update (byte input)
		{
			hasher.Update (new byte[] { input });
		}

		public void BlockUpdate (byte[] input, int inOff, int length)
		{
			hasher.Update (input, inOff, length);
		}

		public int DoFinal (byte[] output, int outOff)
		{
			var outputBytes = hasher.Finish ();
			Array.Copy (outputBytes, 0, output, outOff, outputBytes.Length);
            Reset();
			return outputBytes.Length;
		}

		public void Reset ()
		{
			hasher.Init ();
		}

		public string AlgorithmName {
			get {
				return "BLAKE2B" + outputSize * 8;
			}
		}

		#endregion
	}
}

