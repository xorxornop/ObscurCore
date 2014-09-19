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

namespace ObscurCore.DTO
{
    /// <summary>
    ///     An elliptic curve key.
    /// </summary>
    /// <seealso cref="ECKeypair"/>
    [ProtoContract]
    public class ECKey : IECKey, IDataTransferObject, IEquatable<ECKey>
    {
        /// <summary>
        ///     If <c>true</c>, key is public component of a keypair. Otherwise, key is private component.
        /// </summary>
        /// <remarks>
        ///     Backing field for <see cref="PublicComponent"/>. 
        ///     Not recommended to modify directly as it will bypass logic.</remarks>
        [ProtoIgnore]
        protected bool Public;

        /// <summary>
        ///     If <c>true</c>, key is public component of a keypair. Otherwise, key is private component.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public bool PublicComponent
        {
            get { return Public; }
            set {
                if (value == false) {
                    ConfirmationCanary = null;
                }
                Public = value;
            }
        }

        /// <summary>
        ///     Name of the curve provider. 
        ///     Used to look up relevant domain parameters to decode <see cref="EncodedKey"/>.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string CurveProviderName { get; set; }

        /// <summary>
        ///     Name of the elliptic curve in the <see cref="CurveProviderName"/> provider's selection. 
        ///     Used to look up relevant domain parameters to decode <see cref="EncodedKey"/>.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public string CurveName { get; set; }

        /// <summary>
        ///     Encoded form of the key.
        /// </summary>
        [ProtoMember(4, IsRequired = true)]
        public byte[] EncodedKey { get; set; }

        /// <summary>
        ///     Any additional data required for the <see cref="EncodedKey"/> 
        ///     (for example, special formatting, if any).
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public byte[] AdditionalData { get; set; }

        /// <summary>
        ///     Data used for generating key confirmations. 
        ///     Only applicable when <see cref="PublicComponent"/> is <c>true</c>.
        /// </summary>
        /// <remarks>
        ///     Setting <see cref="PublicComponent"/> to <c>false</c> will remove the current value.
        /// </remarks>
        /// <seealso cref="AuthenticationFunctionConfiguration"/>
        [ProtoMember(6, IsRequired = false)]
        public byte[] ConfirmationCanary { get; set; }

        /// <inheritdoc />
        public bool Equals(ECKey other)
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
            return Equals((ECKey) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = PublicComponent.GetHashCode();
                hashCode = (hashCode * 397) ^ CurveProviderName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ CurveName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ EncodedKey.GetHashCodeExt();
                hashCode = (hashCode * 397) ^ (AdditionalData != null ? AdditionalData.GetHashCodeExt() : 0);
                return hashCode;
            }
        }
    }
}
