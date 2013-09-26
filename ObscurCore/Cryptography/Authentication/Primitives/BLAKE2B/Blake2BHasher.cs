using System;

namespace ObscurCore.Cryptography.Authentication.Primitives.BLAKE2B
{
	public class Blake2BHasher : Hasher
	{
		private readonly Blake2BCore core = new Blake2BCore();
		private ulong[] rawConfig;
		private byte[] key;
		private int outputSizeInBytes;
		private static readonly Blake2BConfig DefaultConfig = new Blake2BConfig();
		
		public override void Init()
		{
			core.Initialize(rawConfig);
			if (key != null)
			{
				core.HashCore(key, 0, key.Length);
			}
		}
		
		public override byte[] Finish()
		{
			var fullResult = core.HashFinal();
			if (outputSizeInBytes != fullResult.Length)
			{
				var result = new byte[outputSizeInBytes];
				Array.Copy(fullResult, result, result.Length);
				return result;
			}
			else return fullResult;
		}
		
		public Blake2BHasher(Blake2BConfig config)
		{
			Reset (config);
		}

		// Added 6-Apr-2013 by _zenith to help existing code conform to IMac interface requirements.
		// Migrated code from ctor
		protected void Reset(Blake2BConfig config) {
			if (config == null)
				config = DefaultConfig;
			rawConfig = Blake2IvBuilder.ConfigB(config, null);
			if (config.Key != null && config.Key.Length != 0)
			{
				key = new byte[128];
				Array.Copy(config.Key, key, config.Key.Length);
			}
			outputSizeInBytes = config.OutputSizeInBytes;
			Init();
		}
		
		public override void Update(byte[] data, int start, int count)
		{
			core.HashCore(data, start, count);
		}
	}
}

