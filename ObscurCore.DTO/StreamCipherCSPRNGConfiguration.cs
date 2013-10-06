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
    /// Configuration object for a CSPRNG based on a stream cipher.
    /// </summary>
    [ProtoContract]
    public class StreamCipherCSPRNGConfiguration : IDataTransferObject, IEquatable<StreamCipherCSPRNGConfiguration>
    {
        [ProtoMember(1, IsRequired = true)]
        public string CipherName { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public byte[] Key { get; set; }

        [ProtoMember(3, IsRequired = false)]
        public byte[] IV { get; set; }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (StreamCipherCSPRNGConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(CipherName, other.CipherName) &&
                   (Key == null ? other.Key == null : Key.SequenceEqual(other.Key)) &&
                   (IV == null ? other.IV == null : IV.SequenceEqual(other.IV));
        }

        public override int GetHashCode () {
            unchecked {
                int hashCode = CipherName.GetHashCode(); // Must not be null!
				hashCode = (hashCode * 397) ^ (Key != null ? Key.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (IV != null ? IV.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
