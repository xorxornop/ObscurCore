using Obscur.Core.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
	class Threefish : BlockCipherTestBase
	{
		public Threefish ()
			: base(BlockCipher.Threefish) {
		}
	}

//	class Threefish512 : BlockCipherTestBase
//	{
//		public Threefish512 ()
//			: base(BlockCipher.Threefish) {
//		}
//	}
}
