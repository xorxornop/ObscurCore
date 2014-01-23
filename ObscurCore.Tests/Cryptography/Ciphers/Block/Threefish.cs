using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Tests.Cryptography.Ciphers.Block
{
	class Threefish : BlockCipherTestBase
	{
		public Threefish ()
			: base(SymmetricBlockCipher.Threefish) {
		}
	}

//	class Threefish512 : BlockCipherTestBase
//	{
//		public Threefish512 ()
//			: base(SymmetricBlockCipher.Threefish) {
//		}
//	}
}
