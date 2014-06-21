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
using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
    public class SymmetricKey : IPossessConfirmationCanary, IEquatable<SymmetricKey>
    {
        /// <summary>
        ///     Key for use in encryption or authentication schemes after key derivation.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public byte[] Key { get; set; }

        /// <summary>
        ///     Types of use for which the key is allowed (operations).
        /// </summary>
        [ProtoMember(2, IsRequired = false)]
        public KeyUseAllowed AllowedUses { get; set; }

        /// <summary>
        ///     Use contexts for which the key is allowed (environment).
        /// </summary>
        [ProtoMember(3, IsRequired = false)]
        public KeyContextAllowed AllowedContexts { get; set; }

        public bool Equals(SymmetricKey other)
        {
            return Equals(other, true);
        }

        /// <summary>
        ///     Data used for generating key confirmations.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public byte[] ConfirmationCanary { get; set; }

        public override int GetHashCode()
        {
            unchecked {
                int hashCode = Key.GetHashCode();
                hashCode = (hashCode * 397) ^ (ConfirmationCanary != null ? ConfirmationCanary.GetHashCode() : 0);
                return hashCode;
            }
        }

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
            return Equals((SymmetricKey) obj);
        }

        public bool Equals(SymmetricKey other, bool constantTime)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }

            if (constantTime == false) {
                return Key.SequenceEqualShortCircuiting(other.Key) &&
                       ConfirmationCanary.SequenceEqualShortCircuiting(other.ConfirmationCanary);
            }
            return Key.SequenceEqualConstantTime(other.Key) &&
                   ConfirmationCanary.SequenceEqualConstantTime(other.ConfirmationCanary);
        }
    }
}
