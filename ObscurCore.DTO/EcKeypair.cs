#region License

// 	Copyright 2014-2014 Matthew Ducker
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

namespace ObscurCore.DTO
{
    /// <summary>
    ///     An elliptic curve keypair.
    /// </summary>
    /// <remarks>
    ///     For use in cryptographic constructions such as ECDH or ECDSA.
    /// </remarks>
    [ProtoContract]
    public class ECKeypair : IECKeypair, IDataTransferObject, IEquatable<ECKeypair>
    {
        /// <summary>
        ///     Name of the curve provider. 
        ///     Used to look up relevant domain parameters to decode 
        ///     <see cref="EncodedPublicKey"/> and <see cref="EncodedPrivateKey"/>.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string CurveProviderName { get; set; }

        /// <summary>
        ///     Name of the elliptic curve in the <see cref="CurveProviderName"/> provider's selection. 
        ///     Used to look up relevant domain parameters to decode 
        ///     <see cref="EncodedPublicKey"/> and <see cref="EncodedPrivateKey"/>.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string CurveName { get; set; }

        /// <summary>
        ///     Encoded form of the public key.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] EncodedPublicKey { get; set; }

        /// <summary>
        ///     Encoded form of the private key.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public byte[] EncodedPrivateKey { get; set; }

        /// <summary>
        ///     Any additional data required for the <see cref="EncodedPublicKey"/> 
        ///     and <see cref="EncodedPrivateKey"/> (for example, special formatting, if any).
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public byte[] AdditionalData { get; set; }

        /// <summary>
        ///     Types of use for which the key is allowed (operations).
        /// </summary>
        [ProtoMember(6, IsRequired = false)]
        public AsymmetricKeyUsePermission UsePermissions { get; set; }

        /// <summary>
        ///     Use contexts for which the key is allowed (environment).
        /// </summary>
        [ProtoMember(7, IsRequired = false)]
        public KeyUseContextPermission ContextPermissions { get; set; }

        /// <summary>
        ///     Data used for generating key confirmations.
        /// </summary>
        /// <seealso cref="AuthenticationFunctionConfiguration"/>
        [ProtoMember(8, IsRequired = false)]
        public byte[] ConfirmationCanary { get; set; }

        /// <summary>
        ///     Exports the public component of the keypair as a DTO.
        /// </summary>
        /// <returns>Public key as <see cref="ECKey"/> DTO.</returns>
        public ECKey ExportPublicKey()
        {
            return new ECKey {
                PublicComponent = true,
                CurveProviderName = String.Copy(CurveProviderName),
                CurveName = String.Copy(CurveName),
                EncodedKey = EncodedPublicKey.DeepCopy(),
                AdditionalData = AdditionalData.DeepCopy(),
                ConfirmationCanary = ConfirmationCanary.DeepCopy()
            };
        }

        /// <summary>
        ///     Exports the private component of the keypair as a DTO object.
        /// </summary>
        /// <returns>Private key as <see cref="ECKey"/> DTO.</returns>
        public ECKey GetPrivateKey()
        {
            return new ECKey {
                PublicComponent = false,
                CurveProviderName = String.Copy(CurveProviderName),
                CurveName = String.Copy(CurveName),
                EncodedKey = EncodedPrivateKey.DeepCopy(),
                AdditionalData = AdditionalData.DeepCopy(),
                ConfirmationCanary = null
            };
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
            return Equals((ECKeypair) obj);
        }

        /// <inheritdoc />
        public bool Equals(ECKeypair other)
        {
            return Equals(other, true);
        }

        /// <inheritdoc />
        public bool Equals(ECKeypair other, bool constantTime)
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
                       (AdditionalData == null
                           ? other.AdditionalData == null
                           : AdditionalData.SequenceEqualShortCircuiting(other.AdditionalData)) &&
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
                   (AdditionalData == null
                           ? other.AdditionalData == null
                           : AdditionalData.SequenceEqualConstantTime(other.AdditionalData)) &&
                   (ConfirmationCanary == null
                       ? other.ConfirmationCanary == null
                       : ConfirmationCanary.SequenceEqualConstantTime(other.ConfirmationCanary));
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = CurveProviderName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ CurveName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ EncodedPublicKey.GetHashCodeExt();
                hashCode = (hashCode * 397) ^ (EncodedPrivateKey != null ? EncodedPrivateKey.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ (AdditionalData != null ? AdditionalData.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ (ConfirmationCanary != null ? ConfirmationCanary.GetHashCodeExt() : 0);
                return hashCode;
            }
        }
    }
}
