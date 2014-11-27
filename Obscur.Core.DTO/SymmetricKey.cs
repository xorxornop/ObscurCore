#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using ProtoBuf;

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     A symmetric key.
    /// </summary>
    /// <remarks>
    ///     For use in cryptographic constructions such as symmetric ciphers,
    ///     MAC functions, and the like.
    /// </remarks>
    [ProtoContract]
    public class SymmetricKey : ISymmetricKey, IDataTransferObject, IEquatable<SymmetricKey>
    {
        #region IEquatable<SymmetricKey> Members

        /// <inheritdoc />
        public bool Equals(SymmetricKey other)
        {
            return Equals(other, true);
        }

        #endregion

        #region ISymmetricKey Members

        /// <summary>
        ///     Key for use in encryption or authentication schemes etc. after further derivation.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public byte[] Key { get; set; }

        /// <summary>
        ///     Any additional data required for the <see cref="Key" />
        ///     (for example, special formatting, if any).
        /// </summary>
        [ProtoMember(2, IsRequired = false)]
        public byte[] AdditionalData { get; set; }

        /// <summary>
        ///     Types of use for which the key is allowed (operations).
        /// </summary>
        [ProtoMember(3, IsRequired = false)]
        public SymmetricKeyUsePermission UsePermissions { get; set; }

        /// <summary>
        ///     Use contexts for which the key is allowed (environment).
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public KeyUseContextPermission ContextPermissions { get; set; }

        /// <summary>
        ///     Data used for generating key confirmations.
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public byte[] ConfirmationCanary { get; set; }

        #endregion

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = Key.GetHashCodeExt();
                hashCode = (hashCode * 397) ^ (AdditionalData != null ? AdditionalData.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ UsePermissions.GetHashCode();
                hashCode = (hashCode * 397) ^ ContextPermissions.GetHashCode();
                hashCode = (hashCode * 397) ^ (ConfirmationCanary != null ? ConfirmationCanary.GetHashCodeExt() : 0);
                return hashCode;
            }
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
            return Equals((SymmetricKey) obj);
        }

        /// <inheritdoc />
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
