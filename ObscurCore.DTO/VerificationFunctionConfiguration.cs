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
using System.Linq;
using ProtoBuf;

namespace ObscurCore.DTO
{
	/// <summary>
	/// Dual-use configuration for verification of data integrity 
	/// (e.g. hash functions) and authenticity (e.g. HMAC functions). 
	/// Used for key confirmation and data integrity checks, etc.
	/// </summary>
	[ProtoContract]
	public class VerificationFunctionConfiguration : IVerificationFunctionConfiguration, IDataTransferObject, 
		IEquatable<VerificationFunctionConfiguration>
	{
		/// <summary>
		/// Category/type of the function primitive, e.g. Digest, MAC, or KDF.
		/// </summary>
		[ProtoMember(1, IsRequired = true)]
		public string FunctionType { get; set; }
        
        /// <summary>
		/// Name of the function used to verify some data (e.g. a key, a payload item, etc.). 
		/// This may be a key derivation function, HMAC function, hash function, etc.
		/// </summary>
		[ProtoMember(2, IsRequired = true)]
		public string FunctionName { get; set; }

		/// <summary>
		/// Configuration for the verification function, where applicable.
		/// </summary>
		/// <remarks>Format of the configuration is that of the consuming type.</remarks>
		[ProtoMember(3, IsRequired = false)]
		public byte[] FunctionConfiguration { get; set; }

		/// <summary>
		/// Salt for the verification function, where applicable.
		/// </summary>
		[ProtoMember(4, IsRequired = false)]
		public byte[] Salt { get; set; }

		/// <summary>
		/// Additional data for the verification function, where applicable.
		/// </summary>
		[ProtoMember(5, IsRequired = false)]
		public byte[] AdditionalData { get; set; }

		/// <summary>
		/// Output of the confirmation/verification scheme given correct input data. 
		/// Usually a KDF or HMAC digest in practice, but varies by scheme.
		/// </summary>
		[ProtoMember(6, IsRequired = true)]
		public byte[] VerifiedOutput { get; set; }

		public override bool Equals (object obj)
		{
			if (ReferenceEquals(null, obj)) return false;
			if (ReferenceEquals(this, obj)) return true;
			if (obj.GetType() != this.GetType()) return false;
			return Equals((VerificationFunctionConfiguration) obj);
		}

		/// <summary>
		/// Indicates whether the current object is equal to another object of the same type.
		/// </summary>
		/// <returns>
		/// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
		/// </returns>
		/// <param name="other">An object to compare with this object.</param>
		public bool Equals (VerificationFunctionConfiguration other) {
			if (ReferenceEquals(null, other)) return false;
			if (ReferenceEquals(this, other)) return true;
			return string.Equals(FunctionName, other.FunctionName) &&
				FunctionConfiguration !=  null ? FunctionConfiguration.SequenceEqual(other.FunctionConfiguration) : true && 
				Salt != null ? Salt.SequenceEqual(other.Salt) : true && 
				VerifiedOutput.SequenceEqual(other.VerifiedOutput);
		}

		/// <summary>
		/// Serves as a hash function for a particular type. 
		/// </summary>
		/// <returns>
		/// A hash code for the current <see cref="T:System.Object"/>.
		/// </returns>
		/// <filterpriority>2</filterpriority>
		public override int GetHashCode () {
			unchecked {
				int hashCode = FunctionName.GetHashCode();
				hashCode = (hashCode * 397) ^ (FunctionConfiguration != null ? FunctionConfiguration.GetHashCode() : 0); // can be null
				hashCode = (hashCode * 397) ^ (Salt != null ? Salt.GetHashCode() : 0); // can be null
				hashCode = (hashCode * 397) ^ (AdditionalData != null ? AdditionalData.GetHashCode() : 0); // can be null
				hashCode = (hashCode * 397) ^ VerifiedOutput.GetHashCode();
				return hashCode;
			}
		}
	}

	public interface IVerificationFunctionConfiguration
	{
        /// <summary>
		/// Category/type of the function primitive, e.g. Digest, MAC, or KDF.
		/// </summary>
		string FunctionType { get; }
        
		/// <summary>
		/// Name of the function used to verify some data (e.g. a key, a payload item, etc.). 
		/// This may be a key derivation function, HMAC function, hash function, etc.
		/// </summary>
		string FunctionName { get; }

		/// <summary>
		/// Configuration for the verification function, where applicable.
		/// </summary>
		/// <remarks>Format of the configuration is that of the consuming type.</remarks>
		byte[] FunctionConfiguration { get; }

		/// <summary>
		/// Salt for the verification function, where applicable.
		/// </summary>
		byte[] Salt { get; }

        /// <summary>
		/// Additional data for the verification function, where applicable.
		/// </summary>
		byte[] AdditionalData { get; set; }

		/// <summary>
		/// Output of the confirmation/verification scheme given correct input data. 
		/// Usually a KDF or HMAC digest in practice, but varies by scheme.
		/// </summary>
		byte[] VerifiedOutput { get; }
	}
}

