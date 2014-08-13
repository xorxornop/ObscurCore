using System;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;

namespace ObscurCore.Cryptography.Support
{
    public class ECDomainParameters
    {
		private readonly ECCurve     _curve;
        private readonly byte[] _seed;
        private readonly ECPoint _g;
        private readonly BigInteger _n;
        private readonly BigInteger _h;

		public ECDomainParameters(
			ECCurve     curve,
			ECPoint     g,
			BigInteger  n)
			: this(curve, g, n, BigInteger.One)
		{
		}

		public ECDomainParameters(
			ECCurve     curve,
			ECPoint     g,
			BigInteger  n,
			BigInteger  h)
			: this(curve, g, n, h, null)
		{
		}

		public ECDomainParameters(
			ECCurve     curve,
			ECPoint     g,
			BigInteger  n,
			BigInteger  h,
			byte[]      seed)
		{
			if (curve == null)
				throw new ArgumentNullException("curve");
			if (g == null)
				throw new ArgumentNullException("g");
			if (n == null)
				throw new ArgumentNullException("n");
			if (h == null)
				throw new ArgumentNullException("h");

			this._curve = curve;
			this._g = g.Normalize();
			this._n = n;
			this._h = h;
			this._seed = seed.DeepCopy();
		}

		public ECCurve Curve
		{
			get { return _curve; }
		}

		public ECPoint G
		{
			get { return _g; }
		}

		public BigInteger N
		{
			get { return _n; }
		}

		public BigInteger H
		{
			get { return _h; }
		}

		public byte[] GetSeed()
		{
			return _seed.DeepCopy();
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			ECDomainParameters other = obj as ECDomainParameters;

			if (other == null)
				return false;

			return Equals(other);
		}

		protected bool Equals(
			ECDomainParameters other)
		{
			return _curve.Equals(other._curve)
				&&	_g.Equals(other._g)
				&&	_n.Equals(other._n)
				&&	_h.Equals(other._h)
				&&	_seed.SequenceEqualShortCircuiting(other._seed);
		}

		public override int GetHashCode()
		{
			return _curve.GetHashCode()
				^	_g.GetHashCode()
				^	_n.GetHashCode()
				^	_h.GetHashCode()
				^	_seed.GetHashCodeExt();
		}
    }
}
