namespace ObscurCore.Cryptography.Support.Math.EllipticCurve.Multiplier
{
	public class ReferenceMultiplier
		: AbstractECMultiplier
	{
		protected override ECPoint MultiplyPositive(ECPoint p, BigInteger k)
		{
            return ECAlgorithms.ReferenceMultiply(p, k);
		}
	}
}
