// From Chaos.NaCl, authored by CodesInChaos (https://github.com/CodesInChaos/Chaos.NaCl)

namespace Obscur.Core.Cryptography.Support.Math.EllipticCurve.Custom.Ed25519
{
    internal static partial class FieldOperations
    {
        /*
        return 1 if f is in {1,3,5,...,q-2}
        return 0 if f is in {0,2,4,...,q-1}

        Preconditions:
        |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
        */
        //int fe_isnegative(const fe f)
        public static int fe_isnegative(ref FieldElement f)
        {
            FieldElement fr;
            fe_reduce(out fr, ref f);
            return fr.x0 & 1;
        }
    }
}