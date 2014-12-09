using System;
using Obscur.Core.Cryptography.Authentication.Primitives;

namespace Obscur.Core.Cryptography.Support.Math.EllipticCurve.Custom.Ed25519
{
    internal static partial class Ed25519Operations
    {
        // Original crypto_sign_open, for reference only
        /*public static int crypto_sign_open(
          byte[] m, out int mlen,
          byte[] sm, int smlen,
          byte[] pk)
        {
            byte[] h = new byte[64];
            byte[] checkr = new byte[32];
            GroupElementP3 A;
            GroupElementP2 R;
            int i;

            mlen = -1;
            if (smlen < 64) return -1;
            if ((sm[63] & 224) != 0) return -1;
            if (GroupOperations.ge_frombytes_negate_vartime(out A, pk, 0) != 0) return -1;

            for (i = 0; i < smlen; ++i) m[i] = sm[i];
            for (i = 0; i < 32; ++i) m[32 + i] = pk[i];
            Sha512BclWrapper.crypto_hash_sha512(h, m, 0, smlen);
            ScalarOperations.sc_reduce(h);

            var sm32 = new byte[32];
            Array.Copy(sm, 32, sm32, 0, 32);
            GroupOperations.ge_double_scalarmult_vartime(out R, h, ref A, sm32);
            GroupOperations.ge_tobytes(checkr, 0, ref R);
            if (Helpers.crypto_verify_32(checkr, sm) != 0)
            {
                for (i = 0; i < smlen; ++i)
                    m[i] = 0;
                return -1;
            }

            for (i = 0; i < smlen - 64; ++i)
                m[i] = sm[64 + i];
            for (i = smlen - 64; i < smlen; ++i)
                m[i] = 0;
            mlen = smlen - 64;
            return 0;
        }*/

        public static bool crypto_sign_verify(
            byte[] sig, int sigoffset,
            byte[] m, int moffset, int mlen,
            byte[] pk, int pkoffset)
        {
            byte[] h;
            byte[] checkr = new byte[32];//todo: remove allocation
            GroupElementP3 A;
            GroupElementP2 R;

            if ((sig[sigoffset + 63] & 224) != 0) return false;
            if (GroupOperations.ge_frombytes_negate_vartime(out A, pk, pkoffset) != 0)
                return false;

			var sha512 = new Sha512Digest ();
			sha512.BlockUpdate(sig, sigoffset, 32);
			sha512.BlockUpdate(pk, pkoffset, 32);
			sha512.BlockUpdate(m, moffset, mlen);

			h = new byte[sha512.OutputSize];
			sha512.DoFinal (h, 0);

            ScalarOperations.sc_reduce(h);

            var sm32 = new byte[32];//todo: remove allocation
            Array.Copy(sig, sigoffset + 32, sm32, 0, 32);
            GroupOperations.ge_double_scalarmult_vartime(out R, h, ref A, sm32);
            GroupOperations.ge_tobytes(checkr, 0, ref R);
			checkr.SequenceEqualConstantTime (checkr);
			return checkr.SequenceEqualConstantTime(0, sig, sigoffset, 32);
        }
    }
}