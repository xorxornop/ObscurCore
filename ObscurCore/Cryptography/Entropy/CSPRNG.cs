//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using System;

namespace ObscurCore.Cryptography.Entropy
{
	/// <summary>
	/// Base class to derive pseudorandom number generators (PRNGs) from.
	/// </summary>
	public abstract class CSPRNG : System.Random
	{
        private readonly byte[] intBuf = new byte[4], dblBuf = new byte[8];

		public override int Next (int maxValue) {
		    var dbl = NextDouble();
            var num = Math.Abs(dbl) * maxValue;
		    num = Math.Round(num, MidpointRounding.ToEven);
		    return (int) num;
		}

        public override int Next(int minValue, int maxValue)
        {
            var dbl = NextDouble();
            var num = (Math.Abs(dbl) * (maxValue - minValue)) + minValue;
		    num = Math.Round(num, MidpointRounding.ToEven);
		    return (int) num;
        }

        //public int NextUnbiasedInt32() {
        //    var intBytes = new byte[4];
        //    NextBytes(intBytes);

        //    var result = 0;
        //    for (var i = 0; i < 3; i++) {
        //        result = (result << 8) | (intBytes[i] & 0xff);
        //    }
        //    result = (result << 8) | (intBytes[3] & 0x7f);

        //    return result;
        //}
		
		public int NextInt() {
			/*var ary = new byte[4];
            NextBytes(ary);
            // The first bit has just as much a chance as being a 0 as it does a 1, with a CSPRNG source - right?
            return BitConverter.ToInt32(ary, 0);*/
			
			return (int) (NextDouble() * Int32.MaxValue); // TODO: Compare the output of this method with that of the UInt32 one!
		}
		
		public UInt32 NextUInt32() {
			//var bytes = new byte[4];
		    var bytes = intBuf;
			NextBytes(bytes);
			return BitConverter.ToUInt32(bytes, 0);
		}

		public override double NextDouble () { return Sample(); }
		
		protected override double Sample () {
			//var bytes = new byte[8];
		    var bytes = dblBuf;
			this.NextBytes(bytes);
			//var ul = BitConverter.ToUInt64(bytes, 0) / (1 << 11); // original
			var ul = BitConverter.ToUInt64(bytes, 0) >> 11; // cleaner version
			return ul / (double) (1UL << 53);
		}

	    public abstract override void NextBytes(byte[] buffer);
	}
}

