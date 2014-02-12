//
//  Copyright 2014  Matthew Ducker
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
using System.Linq;
using ProtoBuf;

namespace ObscurCore.DTO
{
	/// <summary>
	/// Configuration for the PBKDF2 key derivation function.
	/// </summary>
	[ProtoContract]
    public class Pbkdf2Configuration : IDataTransferObject, IEquatable<Pbkdf2Configuration>
	{
	    public Pbkdf2Configuration() {
	        AlgorithmName = "HMACSHA256";
	    }

        /// <summary>
        /// HMAC algorithm to apply iteratively to derive a key. 
        /// </summary>
        /// <remarks>
        /// Currently, only HMACSHA256 is supported.
        /// </remarks>
		[ProtoMember(1, IsRequired = true)]
        public string AlgorithmName { get; set; }

        /// <summary>
        /// Number of times the algorithm will be run sequentially. 
        /// Causes the algorithm to take more cumulative time.
        /// </summary>
        /// <remarks>
        /// General-use cost increase. Use to scale cost/difficulty without changing CPU or memory cost directly, only time.
        /// </remarks>
		[ProtoMember(2, IsRequired = true)]
        public int Iterations { get; set; }

		public override bool Equals (object obj)
		{
			if (ReferenceEquals(null, obj)) return false;
			if (ReferenceEquals(this, obj)) return true;
			if (obj.GetType() != this.GetType()) return false;
			return Equals((Pbkdf2Configuration) obj);
		}

		/// <summary>
		/// Indicates whether the current object is equal to another object of the same type.
		/// </summary>
		/// <returns>
		/// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
		/// </returns>
		/// <param name="other">An object to compare with this object.</param>
		public bool Equals (Pbkdf2Configuration other) {
			if (ReferenceEquals(null, other)) return false;
			if (ReferenceEquals(this, other)) return true;
			return String.Equals(AlgorithmName, other.AlgorithmName) && Iterations == other.Iterations;
		}

		public override int GetHashCode ()
		{
			unchecked {
				int hashCode = AlgorithmName.GetHashCode();
				hashCode = (hashCode * 397) ^ Iterations.GetHashCode();
				return hashCode;
			}
		}
    }
}
