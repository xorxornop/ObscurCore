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
    /// Key Confirmation configuration used to validate the existence and validity 
    /// of keying material at respondent's side without disclosing the key itself.
    /// </summary>
    [ProtoContract]
    public class KeyConfirmationConfiguration : IKeyConfirmationConfiguration, 
        IDataTransferObject, IEquatable<KeyConfirmationConfiguration>
    {
        /// <summary>
        /// Name of the scheme used to verify key validity for a particular item.
        /// </summary>
        /// <remarks>Convert this name to an enumeration when used ly.</remarks>
        [ProtoMember(1, IsRequired = true)]
        public string SchemeName { get; set; }

        /// <summary>
        /// Configuration for the key verification scheme.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(2)]
        public byte[] SchemeConfiguration { get; set; }

        /// <summary>
        /// Salt bytes used for verification whether a key is valid for this item.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] Salt { get; set; }

        /// <summary>
        /// Product of the verification procedure given correct input data (user-supplied key, usually).
        /// </summary>
        [ProtoMember(4, IsRequired = true)]
        public byte[] Hash { get; set; }

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((KeyConfirmationConfiguration) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (KeyConfirmationConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            // No null checks done because if this object is included in a PayloadItem, it is nonsensical to then not have confirmation data.
            return string.Equals(SchemeName, other.SchemeName) &&
                   SchemeConfiguration.SequenceEqual(other.SchemeConfiguration) && 
                   Salt.SequenceEqual(other.Salt) && 
                   Hash.SequenceEqual(other.Hash);
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
                int hashCode = SchemeName.GetHashCode();
                hashCode = (hashCode * 397) ^ (SchemeConfiguration != null ? SchemeConfiguration.GetHashCode() : 0); // can be null
                hashCode = (hashCode * 397) ^ Salt.GetHashCode();
                hashCode = (hashCode * 397) ^ Hash.GetHashCode();
                return hashCode;
            }
        }
    }

    public interface IKeyConfirmationConfiguration
    {
        /// <summary>
        /// Name of the scheme used to verify key validity for a particular item.
        /// </summary>
        /// <remarks>Convert this name to an enumeration when used internally.</remarks>
        string SchemeName { get; }

        /// <summary>
        /// Configuration for the key verification scheme.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] SchemeConfiguration { get; }

        /// <summary>
        /// Salt bytes used for verification whether a key is valid for this item.
        /// </summary>
        byte[] Salt { get; }

        /// <summary>
        /// Product of the verification procedure given correct input data (user-supplied key, usually).
        /// </summary>
        byte[] Hash { get; }
    }
}