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
    public class EcKeypair : IPossessConfirmationCanary
    {
        /// <summary>
        ///     Name of the curve provider. Used to look up relevant domain parameters to interpret the encoded keys.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string CurveProviderName { get; set; }

        /// <summary>
        ///     Name of the elliptic curve in the provider's selection.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string CurveName { get; set; }

        /// <summary>
        ///     Byte-array-encoded form of the public key.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] EncodedPublicKey { get; set; }

        /// <summary>
        ///     Byte-array-encoded form of the private key.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public byte[] EncodedPrivateKey { get; set; }

        /// <summary>
        ///     Data used for generating key confirmations.
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public byte[] ConfirmationCanary { get; set; }

        /// <summary>
        ///     Exports the public component of the keypair as a DTO.
        /// </summary>
        /// <returns>Public key as <see cref="EcKeyConfiguration" /> DTO.</returns>
        public EcKeyConfiguration ExportPublicKey()
        {
            return new EcKeyConfiguration {
                PublicComponent = true,
                CurveProviderName = String.Copy(CurveProviderName),
                CurveName = String.Copy(CurveName),
                EncodedKey = EncodedPublicKey.DeepCopy()
            };
        }

        /// <summary>
        ///     Exports the private component of the keypair as a DTO object.
        /// </summary>
        /// <returns>Public key as <see cref="EcKeyConfiguration" /> DTO.</returns>
        public EcKeyConfiguration GetPrivateKey()
        {
            return new EcKeyConfiguration {
                PublicComponent = false,
                CurveProviderName = String.Copy(CurveProviderName),
                CurveName = String.Copy(CurveName),
                EncodedKey = EncodedPrivateKey.DeepCopy()
            };
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
            return Equals((EcKeypair) obj);
        }

        public bool Equals(EcKeypair other)
        {
            return Equals(other, true);
        }

        public bool Equals(EcKeypair other, bool constantTime)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }

            if (constantTime == false) {
                return String.Equals(CurveProviderName, other.CurveProviderName, StringComparison.OrdinalIgnoreCase) &&
                       String.Equals(CurveName, other.CurveName, StringComparison.OrdinalIgnoreCase) &&
                       EncodedPublicKey.SequenceEqualShortCircuiting(other.EncodedPublicKey) &&
                       (EncodedPrivateKey == null
                           ? other.EncodedPrivateKey == null
                           : EncodedPrivateKey.SequenceEqualShortCircuiting(other.EncodedPrivateKey)) &&
                       (ConfirmationCanary == null
                           ? other.ConfirmationCanary == null
                           : ConfirmationCanary.SequenceEqualShortCircuiting(other.ConfirmationCanary));
            }
            return String.Equals(CurveProviderName, other.CurveProviderName, StringComparison.OrdinalIgnoreCase) &&
                   String.Equals(CurveName, other.CurveName, StringComparison.OrdinalIgnoreCase) &&
                   EncodedPublicKey.SequenceEqualConstantTime(other.EncodedPublicKey) &&
                   (EncodedPrivateKey == null
                       ? other.EncodedPrivateKey == null
                       : EncodedPrivateKey.SequenceEqualConstantTime(other.EncodedPrivateKey)) &&
                   (ConfirmationCanary == null
                       ? other.ConfirmationCanary == null
                       : ConfirmationCanary.SequenceEqualConstantTime(other.ConfirmationCanary));
        }

        public override int GetHashCode()
        {
            unchecked {
                int hashCode = CurveProviderName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ CurveName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ EncodedPublicKey.GetHashCode();
                hashCode = (hashCode * 397) ^ (EncodedPrivateKey != null ? EncodedPrivateKey.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ConfirmationCanary != null ? ConfirmationCanary.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
