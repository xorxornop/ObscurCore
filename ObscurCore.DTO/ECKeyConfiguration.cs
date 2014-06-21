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
using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
    public class EcKeyConfiguration : IDataTransferObject, IEquatable<EcKeyConfiguration>, IEcKeyConfiguration
    {
        /// <summary>
        ///     Any additional data required for the key
        ///     (for example, special formatting, if any).
        /// </summary>
        [ProtoMember(5, IsRequired = true)]
        public byte[] AdditionalData { get; set; }

        [ProtoMember(1, IsRequired = true)]
        public bool PublicComponent { get; set; }

        /// <summary>
        ///     Name of the curve provider. Used to look up relevant domain parameters to interpret the encoded key.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string CurveProviderName { get; set; }

        /// <summary>
        ///     Name of the elliptic curve in the provider's selection.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public string CurveName { get; set; }

        /// <summary>
        ///     Byte-array-encoded form of the key.
        /// </summary>
        [ProtoMember(4, IsRequired = true)]
        public byte[] EncodedKey { get; set; }

        public bool Equals(EcKeyConfiguration other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return PublicComponent == other.PublicComponent &&
                   String.Equals(CurveProviderName, other.CurveProviderName, StringComparison.OrdinalIgnoreCase) &&
                   String.Equals(CurveName, other.CurveName, StringComparison.OrdinalIgnoreCase) &&
                   EncodedKey.SequenceEqualShortCircuiting(other.EncodedKey) &&
                   AdditionalData.SequenceEqualShortCircuiting(other.AdditionalData);
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
            return Equals((EcKeyConfiguration) obj);
        }

        public override int GetHashCode()
        {
            unchecked {
                int hashCode = PublicComponent.GetHashCode();
                hashCode = (hashCode * 397) ^ CurveProviderName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ CurveName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ EncodedKey.GetHashCode();
                return hashCode;
            }
        }
    }

    public interface IEcKeyConfiguration
    {
        bool PublicComponent { get; }

        /// <summary>
        ///     Name of the curve provider. Used to look up relevant domain parameters to interpret the encoded key.
        /// </summary>
        string CurveProviderName { get; }

        /// <summary>
        ///     Name of the elliptic curve in the provider's selection.
        /// </summary>
        string CurveName { get; }

        /// <summary>
        ///     Byte-array-encoded form of the key.
        /// </summary>
        byte[] EncodedKey { get; }
    }
}
