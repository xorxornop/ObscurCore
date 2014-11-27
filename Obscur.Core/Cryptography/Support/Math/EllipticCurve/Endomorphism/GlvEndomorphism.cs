namespace Obscur.Core.Cryptography.Support.Math.EllipticCurve.Endomorphism
{
    public interface GlvEndomorphism
        : ECEndomorphism
    {
        BigInteger[] DecomposeScalar (BigInteger k);
    }
}
