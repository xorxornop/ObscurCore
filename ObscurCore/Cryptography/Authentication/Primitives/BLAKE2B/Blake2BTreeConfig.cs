using System;

namespace ObscurCore.Cryptography.Authentication.Primitives.BLAKE2B
{
	public sealed class Blake2BTreeConfig : ICloneable
	{
		public int IntermediateHashSize { get; set; }
		public int MaxHeight { get; set; }
		public long LeafSize { get; set; }
		public int FanOut { get; set; }
		
		public Blake2BTreeConfig()
		{
			IntermediateHashSize = 64;
		}
		
		public Blake2BTreeConfig Clone()
		{
			var result = new Blake2BTreeConfig();
			result.IntermediateHashSize = IntermediateHashSize;
			result.MaxHeight = MaxHeight;
			result.LeafSize = LeafSize;
			result.FanOut = FanOut;
			return result;
		}
		
		public static Blake2BTreeConfig CreateInterleaved(int parallelism)
		{
			var result = new Blake2BTreeConfig();
			result.FanOut = parallelism;
			result.MaxHeight = 2;
			result.IntermediateHashSize = 64;
			return result;
		}
		
		object ICloneable.Clone()
		{
			return Clone();
		}
	}
}

