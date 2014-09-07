#region License

// 	Copyright 2014-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

#endregion

using System;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support.Math;

namespace ObscurCore.Cryptography.Signing.Primitives
{
    /// <summary>
    ///     A deterministic K calculator based on the algorithm in section 3.2 of RFC 6979.
    /// </summary>
    public class HmacDsaKCalculator
        : IDsaKCalculator
    {
        private readonly HMac _hmac;
        private readonly byte[] _k;
        private readonly byte[] _v;

        private BigInteger n;

        /**
         * Base constructor.
         *
         * @param digest digest to build the HMAC on.
         */

        public HmacDsaKCalculator(IDigest digest)
        {
            this._hmac = new HMac(digest);
            this._v = new byte[_hmac.MacSize];
            this._k = new byte[_hmac.MacSize];
        }

        public virtual bool IsDeterministic
        {
            get { return true; }
        }

        public virtual void Init(BigInteger n, CsRng random)
        {
            throw new InvalidOperationException("Operation not supported.");
        }


        public void Init(BigInteger n, BigInteger d, byte[] message)
        {
            this.n = n;

            _v.FillArray((byte) 0x01);
            _k.FillArray((byte) 0);

            var x = new byte[(n.BitLength + 7) / 8];
            byte[] dVal = d.ToByteArrayUnsigned();

            Array.Copy(dVal, 0, x, x.Length - dVal.Length, dVal.Length);

            var m = new byte[(n.BitLength + 7) / 8];

            BigInteger mInt = BitsToInt(message);

            if (mInt.CompareTo(n) >= 0) {
                mInt = mInt.Subtract(n);
            }

            byte[] mVal = mInt.ToByteArrayUnsigned();

            Array.Copy(mVal, 0, m, m.Length - mVal.Length, mVal.Length);

            _hmac.Init(_k);

            _hmac.BlockUpdate(_v, 0, _v.Length);
            _hmac.Update(0x00);
            _hmac.BlockUpdate(x, 0, x.Length);
            _hmac.BlockUpdate(m, 0, m.Length);

            _hmac.DoFinal(_k, 0);

            _hmac.Init(_k);

            _hmac.BlockUpdate(_v, 0, _v.Length);

            _hmac.DoFinal(_v, 0);

            _hmac.BlockUpdate(_v, 0, _v.Length);
            _hmac.Update(0x01);
            _hmac.BlockUpdate(x, 0, x.Length);
            _hmac.BlockUpdate(m, 0, m.Length);

            _hmac.DoFinal(_k, 0);

            _hmac.Init(_k);

            _hmac.BlockUpdate(_v, 0, _v.Length);

            _hmac.DoFinal(_v, 0);
        }

        public virtual BigInteger NextK()
        {
            var t = new byte[((n.BitLength + 7) / 8)];

            for (;;) {
                int tOff = 0;

                while (tOff < t.Length) {
                    _hmac.BlockUpdate(_v, 0, _v.Length);

                    _hmac.DoFinal(_v, 0);

                    int len = Math.Min(t.Length - tOff, _v.Length);
                    Array.Copy(_v, 0, t, tOff, len);
                    tOff += len;
                }

                BigInteger k = BitsToInt(t);

                if (k.SignValue > 0 && k.CompareTo(n) < 0) {
                    return k;
                }

                _hmac.BlockUpdate(_v, 0, _v.Length);
                _hmac.Update(0x00);

                _hmac.DoFinal(_k, 0);

                _hmac.Init(_k);

                _hmac.BlockUpdate(_v, 0, _v.Length);

                _hmac.DoFinal(_v, 0);
            }
        }

        private BigInteger BitsToInt(byte[] t)
        {
            var v = new BigInteger(1, t);

            if (t.Length * 8 > n.BitLength) {
                v = v.ShiftRight(t.Length * 8 - n.BitLength);
            }

            return v;
        }
    }
}
