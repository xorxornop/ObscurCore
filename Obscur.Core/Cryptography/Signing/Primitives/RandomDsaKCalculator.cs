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
using Obscur.Core.Cryptography.Entropy;
using Obscur.Core.Cryptography.Support.Math;

namespace Obscur.Core.Cryptography.Signing.Primitives
{
    public class RandomDsaKCalculator
        : IDsaKCalculator
    {
        private BigInteger _q;
        private CsRng _random;

        public virtual bool IsDeterministic
        {
            get { return false; }
        }

        public virtual void Init(BigInteger n, CsRng random)
        {
            this._q = n;
            this._random = random;
        }

        public virtual void Init(BigInteger n, BigInteger d, byte[] message)
        {
            throw new InvalidOperationException("Operation not supported");
        }

        public virtual BigInteger NextK()
        {
            int qBitLength = _q.BitLength;

            BigInteger k;
            do {
                k = new BigInteger(qBitLength, _random);
            } while (k.SignValue < 1 || k.CompareTo(_q) >= 0);

            return k;
        }
    }
}
