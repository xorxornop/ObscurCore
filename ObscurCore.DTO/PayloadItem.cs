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
using System.IO;
using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Description of an item in the payload.
    /// </summary>
    [ProtoContract]
    public sealed class PayloadItem : IPayloadItem, IStreamBinding, IDataTransferObject,
        IAuthenticatibleClonable<PayloadItem>, IEquatable<PayloadItem>
    {
        [ProtoIgnore] private Lazy<Stream> _stream;

        public PayloadItem()
        {
            Identifier = Guid.NewGuid();
        }

        internal PayloadItem(out Guid identifier) : this()
        {
            identifier = Identifier;
        }

        internal PayloadItem(Func<Stream> streamBinder, out Guid identifier) : this(out identifier)
        {
            SetStreamBinding(streamBinder);
        }

        public PayloadItem CreateAuthenticatibleClone()
        {
            return new PayloadItem {
                Type = Type,
                RelativePath = RelativePath,
                ExternalLength = ExternalLength,
                InternalLength = InternalLength,
                SymmetricCipher = SymmetricCipher,
                SymmetricCipherKey = SymmetricCipherKey,
                Authentication = Authentication,
                AuthenticationKey = AuthenticationKey,
                AuthenticationVerifiedOutput = null,
                KeyConfirmation = KeyConfirmation,
                KeyConfirmationVerifiedOutput = KeyConfirmationVerifiedOutput,
                KeyDerivation = KeyDerivation
            };
        }

        public bool Equals(PayloadItem other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return
                Type.Equals(other.Type) &&
                String.Equals(RelativePath, other.RelativePath, Type != PayloadItemType.KeyAction
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal) &&
                InternalLength == other.InternalLength && ExternalLength == other.ExternalLength &&
                SymmetricCipher.Equals(other.SymmetricCipher) &&
                Authentication.Equals(other.Authentication) &&
                (AuthenticationKey == null
                    ? other.AuthenticationKey == null
                    : AuthenticationKey.SequenceEqualShortCircuiting(other.AuthenticationKey)) &&
                AuthenticationVerifiedOutput.SequenceEqualShortCircuiting(other.AuthenticationVerifiedOutput) &&
                (KeyConfirmation == null ? other.KeyConfirmation == null : KeyConfirmation.Equals(other.KeyConfirmation)) &&
                (KeyConfirmationVerifiedOutput == null
                    ? other.KeyConfirmationVerifiedOutput == null
                    : KeyConfirmationVerifiedOutput.SequenceEqualShortCircuiting(other.KeyConfirmationVerifiedOutput)) &&
                KeyDerivation == null
                    ? other.KeyDerivation == null
                    : KeyDerivation.Equals((other.KeyDerivation));
        }

        /// <summary>
        ///     Identifier used for stream binding.
        /// </summary>
        /// <remarks>
        ///     Strictly for library internal use only. Do not export this information outside the system.
        /// </remarks>
        [ProtoIgnore]
        public Guid Identifier { get; private set; }

        /// <summary>
        ///     Stream that the payload item is bound to.
        ///     For example, if the item is being read from a payload, the binding will be the location read to.
        /// </summary>
        [ProtoIgnore]
        public Stream StreamBinding
        {
            get { return _stream.Value; }
        }

        /// <summary>
        ///     Item handling behaviour category.
        ///     Key actions should be handled differently from the others.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public PayloadItemType Type { get; set; }

        /// <summary>
        ///     Path of the stored data. 'Path' syntax may correspond to a key-value collection, filesystem, or other hierarchal
        ///     schema.
        ///     Syntax uses '/' to seperate stores/directories. Item names may or may not have extensions (if
        ///     files/binary-data-type).
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string RelativePath { get; set; }

        /// <summary>
        ///     Length of the item outside of the payload, unmodified, as it was before inclusion.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public long ExternalLength { get; set; }

        /// <summary>
        ///     Length of the item inside of the payload,
        ///     excluding any additional length imparted by the payload layout scheme, if any.
        /// </summary>
        [ProtoMember(4, IsRequired = true)]
        public long InternalLength { get; set; }

        /// <summary>
        ///     SymmetricCipher configuration for this payload item.
        /// </summary>
        [ProtoMember(6, IsRequired = true)]
        public CipherConfiguration SymmetricCipher { get; set; }

        /// <summary>
        ///     Ephemeral cryptographic key for encryption of the payload item.
        ///     Required if <see cref="PayloadItem.KeyDerivation" /> is not present.
        /// </summary>
        [ProtoMember(7, IsRequired = false)]
        public byte[] SymmetricCipherKey { get; set; }

        /// <summary>
        ///     Authentication configuration for the payload item.
        ///     Must be of a MAC type.
        /// </summary>
        [ProtoMember(8, IsRequired = true)]
        public AuthenticationFunctionConfiguration Authentication { get; set; }

        /// <summary>
        ///     Cryptographic key for authentication of the payload item.
        ///     Required if <see cref="PayloadItem.KeyDerivation" /> is not present.
        /// </summary>
        [ProtoMember(9, IsRequired = false)]
        public byte[] AuthenticationKey { get; set; }

        /// <summary>
        ///     Output of the authentication scheme given correct input data.
        /// </summary>
        [ProtoMember(10, IsRequired = true)]
        public byte[] AuthenticationVerifiedOutput { get; set; }

        /// <summary>
        ///     Key confirmation configuration for this payload item.
        ///     Used to validate the existence and validity of keying material
        ///     at the respondent's side without disclosing the key itself.
        ///     Required if <see cref="PayloadItem.SymmetricCipherKey" /> and <see cref="PayloadItem.AuthenticationKey" /> are not
        ///     present.
        /// </summary>
        [ProtoMember(11, IsRequired = false)]
        public AuthenticationFunctionConfiguration KeyConfirmation { get; set; }

        /// <summary>
        ///     Output of the key confirmation scheme given the correct key.
        /// </summary>
        [ProtoMember(12, IsRequired = false)]
        public byte[] KeyConfirmationVerifiedOutput { get; set; }

        /// <summary>
        ///     Key derivation configuration for this payload item.
        ///     Used to derive cipher and authentication keys from a single pre-established key.
        ///     Required if <see cref="PayloadItem.SymmetricCipherKey" /> and <see cref="PayloadItem.AuthenticationKey" /> are not
        ///     present.
        /// </summary>
        [ProtoMember(13, IsRequired = false)]
        public KeyDerivationConfiguration KeyDerivation { get; set; }

        /// <summary>
        ///     Clean up the stream binding resource when disposing of the object.
        /// </summary>
        public void Dispose()
        {
            if (_stream.IsValueCreated) {
                _stream.Value.Close();
            }
            SymmetricCipherKey.SecureWipe();
            AuthenticationKey.SecureWipe();
        }


        /// <summary>
        ///     State of stream binding - whether stream is active, or in lazy state. Not the same as
        ///     <see cref="StreamHasBinding" />.
        /// </summary>
        [ProtoIgnore]
        public bool StreamInitialised
        {
            get { return _stream.IsValueCreated; }
        }

        /// <summary>
        ///     State of <see cref="StreamBinding" /> - whether it has a lazy binding (can be activated),
        ///     or none at all (activation is impossible; null reference).
        /// </summary>
        [ProtoIgnore]
        public bool StreamHasBinding
        {
            get { return _stream != null; }
        }

        public void SetStreamBinding(Func<Stream> streamBinding)
        {
            _stream = new Lazy<Stream>(streamBinding);
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
            return Equals((PayloadItem) obj);
        }

        public override int GetHashCode()
        {
            unchecked {
                int hashCode = Type.GetHashCode();
                hashCode = (hashCode * 397) ^ RelativePath.GetHashCode();
                hashCode = (hashCode * 397) ^ InternalLength.GetHashCode();
                hashCode = (hashCode * 397) ^ ExternalLength.GetHashCode();
                hashCode = (hashCode * 397) ^ SymmetricCipher.GetHashCode();
                hashCode = (hashCode * 397) ^ Authentication.GetHashCode();
                hashCode = (hashCode * 397) ^ (AuthenticationKey != null ? AuthenticationKey.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ AuthenticationVerifiedOutput.GetHashCode();
                hashCode = (hashCode * 397) ^ (KeyConfirmation != null ? KeyConfirmation.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^
                           (KeyConfirmationVerifiedOutput != null ? KeyConfirmationVerifiedOutput.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (KeyDerivation != null ? KeyDerivation.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
