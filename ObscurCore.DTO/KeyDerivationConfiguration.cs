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
    /// Key Derivation scheme configuration for deriving valid, secure working key material.
    /// </summary>
    [ProtoContract]
    public class KeyDerivationConfiguration : IDataTransferObject, IEquatable<KeyDerivationConfiguration>
    {
        /// <summary>
        /// Key Derivation Function (KDF) being used to derive valid, secure working key material.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string SchemeName { get; set; }

        /// <summary>
        /// Configuration for the key derivation function.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(2, IsRequired = false)]
        public byte[] SchemeConfiguration { get; set; }

        /// <summary>
        /// Data used by KDF to extend and/or strengthen base key material.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] Salt { get; set; }

        public override bool Equals (object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((KeyDerivationConfiguration) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (KeyDerivationConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Salt.SequenceEqual(other.Salt) &&
                   string.Equals(SchemeName, other.SchemeName) &&
                   (SchemeConfiguration == null ? other.SchemeConfiguration == null : SchemeConfiguration.SequenceEqual(other.SchemeConfiguration));
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
                int hashCode = Salt.GetHashCode();
                hashCode = (hashCode * 397) ^ SchemeName.GetHashCode();
                hashCode = (hashCode * 397) ^ (SchemeConfiguration != null ? SchemeConfiguration.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}