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
using System.IO;
using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Item in the payload of a package.
    /// </summary>
    /// <remarks>
    ///     More accurately, a description of the item: what and where it is. 
    ///     It is to an item what a <see cref="ManifestHeader"/> is to a <see cref="Manifest"/>, 
    ///     with the exception that a manifest header directly precedes a manifest in logical data 
    ///     layout, whereas the same is not true here.
    /// </remarks>
    [ProtoContract]
    public sealed class PayloadItem : IPayloadItem, IDataTransferObject,
        IAuthenticatibleClonable<PayloadItem>, IEquatable<PayloadItem>
    {
        private Lazy<Stream> _stream;

        /// <summary>
        ///     Create a new payload item.
        /// </summary>
        public PayloadItem()
        {
            Identifier = Guid.NewGuid();
        }

        internal PayloadItem(Func<Stream> streamBinder)
        {
            SetStreamBinding(streamBinder);
        }

        /// <summary>
        ///     Identifier used for stream binding.
        /// </summary>
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
        ///     Item type. Used for indicating how an item should be handled.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public PayloadItemType Type { get; set; }

        /// <summary>
        ///     Path and/or name of the stored data.
        /// </summary>
        /// <remarks>
        ///     Path syntax may correspond to a filesystem, key-value collection, or the like.
        /// </remarks>
        [ProtoMember(2, IsRequired = true)]
        public string Path { get; set; }

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
        ///     Name of the format that the content is stored as.
        /// </summary>
        [ProtoMember(5, IsRequired = true)]
        public string FormatName { get; set; }

        /// <summary>
        ///     Data for the format of the content, where applicable 
        ///     (not sufficiently described by <see cref="FormatName"/>).
        /// </summary>
        [ProtoMember(6, IsRequired = true)]
        public byte[] FormatData { get; set; }

        /// <summary>
        ///     Configuration of the cipher used for the encryption of the payload item.
        /// </summary>
        [ProtoMember(7, IsRequired = true)]
        public CipherConfiguration SymmetricCipher { get; set; }

        /// <summary>
        ///     Ephemeral key for encryption of the payload item.
        ///     Required if <see cref="KeyDerivation" /> is not present.
        /// </summary>
        [ProtoMember(8, IsRequired = false)]
        public byte[] SymmetricCipherKey { get; set; }

        /// <summary>
        ///     Configuration for the authentication of the payload item.
        ///     Note: this must be of a MAC type.
        /// </summary>
        [ProtoMember(9, IsRequired = true)]
        public AuthenticationFunctionConfiguration Authentication { get; set; }

        /// <summary>
        ///     Ephemeral key for authentication of the payload item.
        ///     Required if <see cref="KeyDerivation"/> is not present.
        /// </summary>
        [ProtoMember(10, IsRequired = false)]
        public byte[] AuthenticationKey { get; set; }

        /// <summary>
        ///     Output of the <see cref="Authentication"/> scheme, given the correct input and key.
        /// </summary>
        [ProtoMember(11, IsRequired = true)]
        public byte[] AuthenticationVerifiedOutput { get; set; }

        /// <summary>
        ///     Key confirmation configuration for this payload item.
        ///     Used to validate the existence and validity of keying material
        ///     at the respondent's side without disclosing the key itself.
        ///     Required if <see cref="SymmetricCipherKey" /> and <see cref="AuthenticationKey" /> are not
        ///     present.
        /// </summary>
        [ProtoMember(12, IsRequired = false)]
        public AuthenticationFunctionConfiguration KeyConfirmation { get; set; }

        /// <summary>
        ///     Output of the <see cref="KeyConfirmation"/> scheme, given the correct key.
        /// </summary>
        [ProtoMember(13, IsRequired = false)]
        public byte[] KeyConfirmationVerifiedOutput { get; set; }

        /// <summary>
        ///     Key derivation configuration for this payload item.
        ///     Used to derive cipher and authentication keys from a single key.
        ///     Required if <see cref="SymmetricCipherKey" /> and <see cref="AuthenticationKey" /> are not
        ///     present.
        /// </summary>
        [ProtoMember(14, IsRequired = false)]
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
        ///     or none at all (activation is impossible: null reference).
        /// </summary>
        [ProtoIgnore]
        public bool StreamHasBinding
        {
            get { return _stream != null; }
        }

        /// <summary>
        ///     Assigns a function that returns a <see cref="Stream"/> 
        ///     associated with this item.
        /// </summary>
        /// <param name="streamBinding"></param>
        public void SetStreamBinding(Func<Stream> streamBinding)
        {
            _stream = new Lazy<Stream>(streamBinding);
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
            return Equals((PayloadItem) obj);
        }

        /// <inheritdoc />
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
                String.Equals(Path, other.Path, Type != PayloadItemType.KeyAction
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

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = Type.GetHashCode();
                hashCode = (hashCode * 397) ^ Path.GetHashCode();
                //hashCode = (hashCode * 397) ^ InternalLength.GetHashCode();
                //hashCode = (hashCode * 397) ^ ExternalLength.GetHashCode();
                //hashCode = (hashCode * 397) ^ SymmetricCipher.GetHashCode();
                //hashCode = (hashCode * 397) ^ Authentication.GetHashCode();
                //hashCode = (hashCode * 397) ^ (AuthenticationKey != null ? AuthenticationKey.GetHashCode() : 0);
                //hashCode = (hashCode * 397) ^ AuthenticationVerifiedOutput.GetHashCode();
                //hashCode = (hashCode * 397) ^ (KeyConfirmation != null ? KeyConfirmation.GetHashCode() : 0);
                //hashCode = (hashCode * 397) ^
                //           (KeyConfirmationVerifiedOutput != null ? KeyConfirmationVerifiedOutput.GetHashCode() : 0);
                //hashCode = (hashCode * 397) ^ (KeyDerivation != null ? KeyDerivation.GetHashCode() : 0);
                return hashCode;
            }
        }

        /// <inheritdoc />
        public PayloadItem CreateAuthenticatibleClone()
        {
            return new PayloadItem {
                Type = Type,
                Path = Path,
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

        /// <inheritdoc />
        public PayloadItem CloneSafely()
        {
            return new PayloadItem {
                Type = Type,
                Path = String.Copy(this.Path),
                ExternalLength = ExternalLength,
                InternalLength = InternalLength,
                SymmetricCipher = this.SymmetricCipher.CloneSafely(),
                SymmetricCipherKey = null,
                Authentication = Authentication.CloneSafely(),
                AuthenticationKey = null,
                AuthenticationVerifiedOutput = null,
                KeyConfirmation = KeyConfirmation.CloneSafely(),
                KeyConfirmationVerifiedOutput = null,
                KeyDerivation = KeyDerivation.CloneSafely()
            };
        }
    }
}
