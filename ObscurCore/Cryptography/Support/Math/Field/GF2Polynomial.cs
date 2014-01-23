using System;

namespace ObscurCore.Cryptography.Support.Math.Field
{
    internal class GF2Polynomial
        : IPolynomial
    {
        protected readonly int[] exponents;

        internal GF2Polynomial(int[] exponents)
        {
			this.exponents = exponents.CloneArray ();
        }

        public virtual int Degree
        {
            get { return exponents[exponents.Length - 1]; }
        }

        public virtual int[] GetExponentsPresent()
        {
			return exponents.CloneArray ();
        }

        public override bool Equals(object obj)
        {
            if (this == obj)
            {
                return true;
            }
            GF2Polynomial other = obj as GF2Polynomial;
            if (null == other)
            {
                return false;
            }
			return exponents.SequenceEqual(other.exponents);
        }

        public override int GetHashCode()
        {
			return exponents.GetHashCodeExt();
        }
    }
}
