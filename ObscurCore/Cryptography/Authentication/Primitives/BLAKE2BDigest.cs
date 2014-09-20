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

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	public class Blake2BDigest : IHash
	{
		private readonly Blake2BCore _core = new Blake2BCore();
		protected int outputSize;

		private ulong[] rawConfig;
		private byte[] key;

		private static readonly Blake2BCore.Blake2BConfig DefaultConfig = new Blake2BCore.Blake2BConfig();

		public Blake2BDigest (int size, bool bits) : this(size, bits, true)
		{
		}

		protected Blake2BDigest(int size, bool bits, bool init) {
            if (bits) size /= 8;
			outputSize = size;
			if (!init) return;

			var config = new Blake2BCore.Blake2BConfig {
				Key = null,
				Salt = null,
				Personalization = null,
				OutputSizeInBytes = size,
			};

			InitCore (config);
		}

		protected void InitCore (Blake2BCore.Blake2BConfig config) {
            rawConfig = Blake2BCore.ConfigB(config ?? DefaultConfig);
			if (config.Key != null && config.Key.Length != 0) {
				key = new byte[128];
				config.Key.CopyBytes(0, key, 0, config.Key.Length);
			}
			outputSize = config.OutputSizeInBytes;
			_core.Initialize (rawConfig);
			if (key.IsNullOrZeroLength() == false) {
				_core.HashCore (key, 0, key.Length);
			}
		}

		#region IDigest implementation

	    public int DigestSize {
	        get { return outputSize; }
	    }

	    public int ByteLength {
	        get { return 128; }
	    }

	    public void Update (byte input)
		{
			_core.HashCore (new byte[] { input }, 0, 1);
		}

		public void BlockUpdate (byte[] input, int inOff, int length)
		{
			_core.HashCore (input, inOff, length);
		}

		public int DoFinal (byte[] output, int outOff)
		{
			var fullResult = _core.HashFinal();
			fullResult.CopyBytes(0, output, outOff, outputSize);
			Reset ();
			return outputSize;
		}

		public void Reset ()
		{
			if (rawConfig == null) {
				throw new InvalidOperationException ();
			}
			_core.Initialize (rawConfig);
			if (key.IsNullOrZeroLength() == false) {
				_core.HashCore(key, 0, key.Length);
			}
		}

		public string AlgorithmName 
        {
			get { return "BLAKE2B-" + outputSize * 8; }
		}

		#endregion
	}
}

