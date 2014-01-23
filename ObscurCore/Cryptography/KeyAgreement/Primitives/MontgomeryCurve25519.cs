using System;
using ObscurCore.Cryptography.Signing.Primitives.Ed25519Ref10;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
	// This class is mainly for compatibility with NaCl's Curve25519 implementation
	// If you don't need that compatibility, use Ed25519.KeyExchange
	public static class MontgomeryCurve25519
	{
		public static readonly int PublicKeySizeInBytes = 32;
		public static readonly int PrivateKeySizeInBytes = 32;
		public static readonly int SharedKeySizeInBytes = 32;

		public static byte[] GetPublicKey(byte[] privateKey)
		{
			if (privateKey == null)
				throw new ArgumentNullException("privateKey");
			if (privateKey.Length != PrivateKeySizeInBytes)
				throw new ArgumentException("privateKey.Length must be 32");
			var publicKey = new byte[32];
			GetPublicKey(new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
			return publicKey;
		}

		static readonly byte[] _basePoint = new byte[32]
		{
			9, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0 ,0, 0, 0, 0, 0,
			0, 0, 0 ,0, 0, 0, 0, 0,
			0, 0, 0 ,0, 0, 0, 0, 0
		};

		public static void GetPublicKey(ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
		{
			if (publicKey.Array == null)
				throw new ArgumentNullException("publicKey.Array");
			if (privateKey.Array == null)
				throw new ArgumentNullException("privateKey.Array");
			if (publicKey.Count != PublicKeySizeInBytes)
				throw new ArgumentException("privateKey.Count must be 32");
			if (privateKey.Count != PrivateKeySizeInBytes)
				throw new ArgumentException("privateKey.Count must be 32");

			// hack: abusing publicKey as temporary storage
			// todo: remove hack
			for (int i = 0; i < 32; i++)
			{
				publicKey.Array[publicKey.Offset + i] = privateKey.Array[privateKey.Offset + i];
			}
			publicKey.Array[publicKey.Offset + 0] &= 248;
			publicKey.Array[publicKey.Offset + 31] &= 63;
			publicKey.Array[publicKey.Offset + 31] |= 64;

			GroupElementP3 A;
			GroupOperations.ge_scalarmult_base(out A, publicKey.Array, publicKey.Offset);
			FieldElement publicKeyFE;
			EdwardsToMontgomeryX(out publicKeyFE, ref A.Y, ref A.Z);
			FieldOperations.fe_tobytes(publicKey.Array, publicKey.Offset, ref publicKeyFE);
		}

//		// hashes like the Curve25519 paper says
//		internal static void KeyExchangeOutputHashCurve25519Paper(byte[] sharedKey, int offset)
//		{
//			//c = Curve25519output
//			const UInt32 c0 = 'C' | 'u' << 8 | 'r' << 16 | (UInt32)'v' << 24;
//			const UInt32 c1 = 'e' | '2' << 8 | '5' << 16 | (UInt32)'5' << 24;
//			const UInt32 c2 = '1' | '9' << 8 | 'o' << 16 | (UInt32)'u' << 24;
//			const UInt32 c3 = 't' | 'p' << 8 | 'u' << 16 | (UInt32)'t' << 24;
//
//			Array16<UInt32> salsaState;
//			salsaState.x0 = c0;
//			salsaState.x1 = Pack.LE_To_UInt32(sharedKey, offset + 0);
//			salsaState.x2 = 0;
//			salsaState.x3 = Pack.LE_To_UInt32(sharedKey, offset + 4);
//			salsaState.x4 = Pack.LE_To_UInt32(sharedKey, offset + 8);
//			salsaState.x5 = c1;
//			salsaState.x6 = Pack.LE_To_UInt32(sharedKey, offset + 12);
//			salsaState.x7 = 0;
//			salsaState.x8 = 0;
//			salsaState.x9 = Pack.LE_To_UInt32(sharedKey, offset + 16);
//			salsaState.x10 = c2;
//			salsaState.x11 = Pack.LE_To_UInt32(sharedKey, offset + 20);
//			salsaState.x12 = Pack.LE_To_UInt32(sharedKey, offset + 24);
//			salsaState.x13 = 0;
//			salsaState.x14 = Pack.LE_To_UInt32(sharedKey, offset + 28);
//			salsaState.x15 = c3;
//			SalsaCore.Salsa(out salsaState, ref salsaState, 20);
//
//			Pack.UInt32_To_LE(salsaState.x0, sharedKey, offset + 0);
//			Pack.UInt32_To_LE(salsaState.x1, sharedKey, offset + 4);
//			Pack.UInt32_To_LE(salsaState.x2, sharedKey, offset + 8);
//			Pack.UInt32_To_LE(salsaState.x3, sharedKey, offset + 12);
//			Pack.UInt32_To_LE(salsaState.x4, sharedKey, offset + 16);
//			Pack.UInt32_To_LE(salsaState.x5, sharedKey, offset + 20);
//			Pack.UInt32_To_LE(salsaState.x6, sharedKey, offset + 24);
//			Pack.UInt32_To_LE(salsaState.x7, sharedKey, offset + 28);
//		}

		private static readonly byte[] _zero16 = new byte[16];

		// hashes like the NaCl paper says instead i.e. HSalsa(x,0)
		internal static void KeyExchangeOutputHashNaCl(byte[] sharedKey, int offset)
		{
			Salsa20.HSalsa20(sharedKey, offset, sharedKey, offset, _zero16, 0);
		}


		/// <summary>
		/// Performs a Curve25519 key exchange and hashes the 
		/// resulting key as per Daniel J. Bernstein's NaCl library.
		/// </summary>
		/// <returns>The exchange.</returns>
		/// <param name="publicKey">Public key.</param>
		/// <param name="privateKey">Private key.</param>
		public static byte[] KeyExchange(byte[] publicKey, byte[] privateKey)
		{
			var sharedKey = new byte[SharedKeySizeInBytes];
			KeyExchange(new ArraySegment<byte>(sharedKey), new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
			return sharedKey;
		}

		public static void KeyExchange(ArraySegment<byte> sharedKey, ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
		{
			if (sharedKey.Array == null)
				throw new ArgumentNullException("sharedKey.Array");
			if (publicKey.Array == null)
				throw new ArgumentNullException("publicKey.Array");
			if (privateKey.Array == null)
				throw new ArgumentNullException("privateKey");
			if (sharedKey.Count != 32)
				throw new ArgumentException("sharedKey.Count != 32");
			if (publicKey.Count != 32)
				throw new ArgumentException("publicKey.Count != 32");
			if (privateKey.Count != 32)
				throw new ArgumentException("privateKey.Count != 32");
			MontgomeryOperations.scalarmult(sharedKey.Array, sharedKey.Offset, privateKey.Array, privateKey.Offset, publicKey.Array, publicKey.Offset);
			KeyExchangeOutputHashNaCl(sharedKey.Array, sharedKey.Offset);
		}

		internal static void EdwardsToMontgomeryX(out FieldElement montgomeryX, ref FieldElement edwardsY, ref FieldElement edwardsZ)
		{
			FieldElement tempX, tempZ;
			FieldOperations.fe_add(out tempX, ref edwardsZ, ref edwardsY);
			FieldOperations.fe_sub(out tempZ, ref edwardsZ, ref edwardsY);
			FieldOperations.fe_invert(out tempZ, ref tempZ);
			FieldOperations.fe_mul(out montgomeryX, ref tempX, ref tempZ);
		}

		private class Salsa20
		{
			public const uint SalsaConst0 = 0x61707865;
			public const uint SalsaConst1 = 0x3320646e;
			public const uint SalsaConst2 = 0x79622d32;
			public const uint SalsaConst3 = 0x6b206574;

			public static void HSalsa20(byte[] output, int outputOffset, byte[] key, int keyOffset, byte[] nonce, int nonceOffset)
			{
				Array16<UInt32> state;
				state.x0 = SalsaConst0;
				state.x1 = Pack.LE_To_UInt32(key, keyOffset + 0);
				state.x2 = Pack.LE_To_UInt32(key, keyOffset + 4);
				state.x3 = Pack.LE_To_UInt32(key, keyOffset + 8);
				state.x4 = Pack.LE_To_UInt32(key, keyOffset + 12);
				state.x5 = SalsaConst1;
				state.x6 = Pack.LE_To_UInt32(nonce, nonceOffset + 0);
				state.x7 = Pack.LE_To_UInt32(nonce, nonceOffset + 4);
				state.x8 = Pack.LE_To_UInt32(nonce, nonceOffset + 8);
				state.x9 = Pack.LE_To_UInt32(nonce, nonceOffset + 12);
				state.x10 = SalsaConst2;
				state.x11 = Pack.LE_To_UInt32(key, keyOffset + 16);
				state.x12 = Pack.LE_To_UInt32(key, keyOffset + 20);
				state.x13 = Pack.LE_To_UInt32(key, keyOffset + 24);
				state.x14 = Pack.LE_To_UInt32(key, keyOffset + 28);
				state.x15 = SalsaConst3;

				SalsaCore.HSalsa(out state, ref state, 20);

				Pack.UInt32_To_LE(state.x0, output, outputOffset + 0);
				Pack.UInt32_To_LE(state.x5, output, outputOffset + 4);
				Pack.UInt32_To_LE(state.x10, output, outputOffset + 8);
				Pack.UInt32_To_LE(state.x15, output, outputOffset + 12);
				Pack.UInt32_To_LE(state.x6, output, outputOffset + 16);
				Pack.UInt32_To_LE(state.x7, output, outputOffset + 20);
				Pack.UInt32_To_LE(state.x8, output, outputOffset + 24);
				Pack.UInt32_To_LE(state.x9, output, outputOffset + 28);
			}
		}

		private static class SalsaCore
		{
			public static void HSalsa(out Array16<UInt32> output, ref Array16<UInt32> input, int rounds)
			{
				if (rounds % 2 != 0)
					throw new ArgumentException("Rounds must be even");
				int doubleRounds = rounds / 2;

				UInt32 x0 = input.x0;
				UInt32 x1 = input.x1;
				UInt32 x2 = input.x2;
				UInt32 x3 = input.x3;
				UInt32 x4 = input.x4;
				UInt32 x5 = input.x5;
				UInt32 x6 = input.x6;
				UInt32 x7 = input.x7;
				UInt32 x8 = input.x8;
				UInt32 x9 = input.x9;
				UInt32 x10 = input.x10;
				UInt32 x11 = input.x11;
				UInt32 x12 = input.x12;
				UInt32 x13 = input.x13;
				UInt32 x14 = input.x14;
				UInt32 x15 = input.x15;

				for (int i = 0; i < doubleRounds; i++)
				{
					UInt32 y;

					// row 0
					y = x0 + x12;
					x4 ^= (y << 7) | (y >> (32 - 7));
					y = x4 + x0;
					x8 ^= (y << 9) | (y >> (32 - 9));
					y = x8 + x4;
					x12 ^= (y << 13) | (y >> (32 - 13));
					y = x12 + x8;
					x0 ^= (y << 18) | (y >> (32 - 18));

					// row 1
					y = x5 + x1;
					x9 ^= (y << 7) | (y >> (32 - 7));
					y = x9 + x5;
					x13 ^= (y << 9) | (y >> (32 - 9));
					y = x13 + x9;
					x1 ^= (y << 13) | (y >> (32 - 13));
					y = x1 + x13;
					x5 ^= (y << 18) | (y >> (32 - 18));

					// row 2
					y = x10 + x6;
					x14 ^= (y << 7) | (y >> (32 - 7));
					y = x14 + x10;
					x2 ^= (y << 9) | (y >> (32 - 9));
					y = x2 + x14;
					x6 ^= (y << 13) | (y >> (32 - 13));
					y = x6 + x2;
					x10 ^= (y << 18) | (y >> (32 - 18));

					// row 3
					y = x15 + x11;
					x3 ^= (y << 7) | (y >> (32 - 7));
					y = x3 + x15;
					x7 ^= (y << 9) | (y >> (32 - 9));
					y = x7 + x3;
					x11 ^= (y << 13) | (y >> (32 - 13));
					y = x11 + x7;
					x15 ^= (y << 18) | (y >> (32 - 18));

					// column 0
					y = x0 + x3;
					x1 ^= (y << 7) | (y >> (32 - 7));
					y = x1 + x0;
					x2 ^= (y << 9) | (y >> (32 - 9));
					y = x2 + x1;
					x3 ^= (y << 13) | (y >> (32 - 13));
					y = x3 + x2;
					x0 ^= (y << 18) | (y >> (32 - 18));

					// column 1
					y = x5 + x4;
					x6 ^= (y << 7) | (y >> (32 - 7));
					y = x6 + x5;
					x7 ^= (y << 9) | (y >> (32 - 9));
					y = x7 + x6;
					x4 ^= (y << 13) | (y >> (32 - 13));
					y = x4 + x7;
					x5 ^= (y << 18) | (y >> (32 - 18));

					// column 2
					y = x10 + x9;
					x11 ^= (y << 7) | (y >> (32 - 7));
					y = x11 + x10;
					x8 ^= (y << 9) | (y >> (32 - 9));
					y = x8 + x11;
					x9 ^= (y << 13) | (y >> (32 - 13));
					y = x9 + x8;
					x10 ^= (y << 18) | (y >> (32 - 18));

					// column 3
					y = x15 + x14;
					x12 ^= (y << 7) | (y >> (32 - 7));
					y = x12 + x15;
					x13 ^= (y << 9) | (y >> (32 - 9));
					y = x13 + x12;
					x14 ^= (y << 13) | (y >> (32 - 13));
					y = x14 + x13;
					x15 ^= (y << 18) | (y >> (32 - 18));
				}

				output.x0 = x0;
				output.x1 = x1;
				output.x2 = x2;
				output.x3 = x3;
				output.x4 = x4;
				output.x5 = x5;
				output.x6 = x6;
				output.x7 = x7;
				output.x8 = x8;
				output.x9 = x9;
				output.x10 = x10;
				output.x11 = x11;
				output.x12 = x12;
				output.x13 = x13;
				output.x14 = x14;
				output.x15 = x15;
			}

			public static void Salsa(out Array16<UInt32> output, ref Array16<UInt32> input, int rounds)
			{
				Array16<UInt32> temp;
				HSalsa(out temp, ref input, rounds);
				output.x0 = temp.x0 + input.x0;
				output.x1 = temp.x1 + input.x1;
				output.x2 = temp.x2 + input.x2;
				output.x3 = temp.x3 + input.x3;
				output.x4 = temp.x4 + input.x4;
				output.x5 = temp.x5 + input.x5;
				output.x6 = temp.x6 + input.x6;
				output.x7 = temp.x7 + input.x7;
				output.x8 = temp.x8 + input.x8;
				output.x9 = temp.x9 + input.x9;
				output.x10 = temp.x10 + input.x10;
				output.x11 = temp.x11 + input.x11;
				output.x12 = temp.x12 + input.x12;
				output.x13 = temp.x13 + input.x13;
				output.x14 = temp.x14 + input.x14;
				output.x15 = temp.x15 + input.x15;
			}
		}
	}
}

