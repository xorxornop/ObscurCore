namespace Obscur.Core.Cryptography.Support.Math.Field
{
    public interface IPolynomial
    {
        int Degree { get; }

        //BigInteger[] GetCoefficients();

        int[] GetExponentsPresent ();

        //Term[] GetNonZeroTerms();
    }
}
