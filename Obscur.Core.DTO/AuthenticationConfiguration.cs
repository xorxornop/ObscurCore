#region License

// 	Copyright 2013-2014 Matthew Ducker
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
using ProtoBuf;

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Configuration of a function or scheme used for checking the authenticity 
    ///     (e.g. MAC functions) and/or integrity (e.g. hash functions) of data.
    /// </summary>
    [ProtoContract]
    public class AuthenticationConfiguration : IDataTransferObject, 
        ICloneableSafely<AuthenticationConfiguration>, IEquatable<AuthenticationConfiguration>, IAuthenticationConfiguration
    {
        /// <summary>
        ///     Category/type of the function primitive, e.g. Digest, MAC, or KDF.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public AuthenticationFunctionType FunctionType { get; set; }

        /// <summary>
        ///     Name of the function used to authenticate/verify some data (e.g. a key, a payload item, etc.).
        ///     This may be a hash function, MAC function, key derivation function, etc.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string FunctionName { get; set; }

        /// <summary>
        ///     Configuration for the authentication function, where applicable.
        /// </summary>
        [ProtoMember(3, IsRequired = false)]
        public byte[] FunctionConfiguration { get; set; }

        /// <summary>
        ///     Size of the key in bits for the authentication function, where applicable.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public int? KeySizeBits { get; set; }

        /// <summary>
        ///     Nonce/initialisation vector for the authentication function, where applicable.
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public byte[] Nonce { get; set; }

        /// <summary>
        ///     Salt for the authentication function, where applicable.
        /// </summary>
        [ProtoMember(6, IsRequired = false)]
        public byte[] Salt { get; set; }

        /// <summary>
        ///     Additional data for the authentication function, where applicable.
        /// </summary>
        [ProtoMember(7, IsRequired = false)]
        public byte[] AdditionalData { get; set; }

        /// <summary>
        ///     Size of the output in bits from the authentication function, where applicable.
        /// </summary>
        [ProtoMember(8, IsRequired = false)]
        public int? OutputSizeBits { get; set; }

        /// <inheritdoc />
        public bool Equals(AuthenticationConfiguration other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }

            return String.Equals(FunctionName, other.FunctionName, StringComparison.OrdinalIgnoreCase) && 
                FunctionConfiguration == null ? other.FunctionConfiguration == null : FunctionConfiguration.SequenceEqualShortCircuiting(other.FunctionConfiguration) && 
                KeySizeBits.Equals(other.KeySizeBits) &&
                Nonce == null ? other.Nonce == null : Nonce.SequenceEqualShortCircuiting(other.Nonce) && 
                Salt == null ? other.Salt == null : Salt.SequenceEqualShortCircuiting(other.Salt) && 
                AdditionalData == null ? other.AdditionalData == null : AdditionalData.SequenceEqualShortCircuiting(other.AdditionalData) && 
                OutputSizeBits.Equals(other.OutputSizeBits);
        }

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) {
                return false;
            }
            if (ReferenceEquals(this, obj)) {
                return true;
            }
            if (obj.GetType() != GetType()) {
                return false;
            }
            return Equals((AuthenticationConfiguration) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = FunctionType.GetHashCode();
                hashCode = (hashCode * 397) ^ FunctionName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ (FunctionConfiguration != null ? FunctionConfiguration.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ (KeySizeBits.HasValue ? KeySizeBits.Value.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Nonce != null ? Nonce.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ (Salt != null ? Salt.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ (AdditionalData != null ? AdditionalData.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ (OutputSizeBits.HasValue ? OutputSizeBits.Value.GetHashCode() : 0);
                return hashCode;
            }
        }

        /// <inheritdoc />
        public AuthenticationConfiguration CloneSafely()
        {
            return new AuthenticationConfiguration {
                FunctionType = FunctionType,
                FunctionName = String.Copy(FunctionName),
                FunctionConfiguration = FunctionConfiguration.DeepCopy(),
                KeySizeBits = KeySizeBits,
                Nonce = null,
                Salt = null,
                AdditionalData = null
            };
        }
    }
}
