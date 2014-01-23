using System;
using ObscurCore.Cryptography.Authentication.Primitives;

// From Chaos.NaCl, authored by CodesInChaos (https://github.com/CodesInChaos/Chaos.NaCl)
// Modified to use ObscurCore SHA512

namespace ObscurCore.Cryptography.Signing.Primitives.Ed25519Ref10
{
    internal static partial class Ed25519Operations
    {
        public static void crypto_sign_keypair(byte[] pk, int pkoffset, byte[] sk, int skoffset, byte[] seed, int seedoffset)
        {
            GroupElementP3 A;
            int i;

            Array.Copy(seed, seedoffset, sk, skoffset, 32);

			var sha512 = new Sha512Digest ();
			sha512.BlockUpdate(sk, skoffset, 32);
			byte[] h = new byte[sha512.DigestSize];
			sha512.DoFinal (h, 0);

            h[0] &= 248;
            h[31] &= 63;
            h[31] |= 64;

            GroupOperations.ge_scalarmult_base(out A, h, 0);
            GroupOperations.ge_p3_tobytes(pk, pkoffset, ref A);

			for (i = 0; i < 32; ++i) {
				sk[skoffset + 32 + i] = pk[pkoffset + i];
			}
			h.SecureWipe();
        }
    }
}
