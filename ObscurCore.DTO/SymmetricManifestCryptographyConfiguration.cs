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
    ///     Configuration of a symmetric cryptosystem to secure a package manifest.
    /// </summary>
    [ProtoContract]
    public class SymmetricManifestCryptographyConfiguration : IManifestCryptographySchemeConfiguration,
        IDataTransferObject, IAuthenticatibleClonable<SymmetricManifestCryptographyConfiguration>,
        ICloneableSafely<SymmetricManifestCryptographyConfiguration>, IEquatable<SymmetricManifestCryptographyConfiguration>
    {
        /// <inheritdoc />
        public SymmetricManifestCryptographyConfiguration CreateAuthenticatibleClone()
        {
            return new SymmetricManifestCryptographyConfiguration {
                KeyConfirmation = KeyConfirmation,
                KeyConfirmationVerifiedOutput = KeyConfirmationVerifiedOutput,
                KeyDerivation = KeyDerivation,
                SymmetricCipher = SymmetricCipher,
                Authentication = Authentication,
                AuthenticationVerifiedOutput = null
            };
        }

        /// <inheritdoc />
        public bool Equals(SymmetricManifestCryptographyConfiguration other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return
                (KeyConfirmation == null ? other.KeyConfirmation == null : KeyConfirmation.Equals(other.KeyConfirmation)) &&
                (KeyConfirmationVerifiedOutput == null
                    ? other.KeyConfirmation == null
                    : KeyConfirmationVerifiedOutput.SequenceEqualShortCircuiting(other.KeyConfirmationVerifiedOutput)) &&
                KeyDerivation.Equals(other.KeyDerivation) &&
                SymmetricCipher.Equals(other.SymmetricCipher) &&
                Authentication.Equals(other.Authentication) &&
                AuthenticationVerifiedOutput.SequenceEqualShortCircuiting(other.AuthenticationVerifiedOutput);
        }

        /// <summary>
        ///     Configuration of the cipher used in encryption of the manifest.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public CipherConfiguration SymmetricCipher { get; set; }

        /// <summary>
        ///     Configuration of the function/scheme used in authentication of the manifest. 
        ///     Note: this must be of a MAC type.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public AuthenticationFunctionConfiguration Authentication { get; set; }

        /// <summary>
        ///     Output of the <see cref="Authentication"/> scheme, given the correct input and key.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] AuthenticationVerifiedOutput { get; set; }

        /// <summary>
        ///     Configuration for the key confirmation scheme used to validate the existence and
        ///     validity of keying material at respondent's side without disclosing the key itself.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public AuthenticationFunctionConfiguration KeyConfirmation { get; set; }

        /// <summary>
        ///     Output of the <see cref="KeyConfirmation"/> scheme, given the correct key.
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public byte[] KeyConfirmationVerifiedOutput { get; set; }

        /// <summary>
        ///     Configuration for the scheme used to derive cipher and authentication keys 
        ///     from the initial pre-established/known key.
        /// </summary>
        [ProtoMember(6, IsRequired = true)]
        public KeyDerivationConfiguration KeyDerivation { get; set; }

        /// <inheritdoc />
        public SymmetricManifestCryptographyConfiguration CloneSafely()
        {
            return new SymmetricManifestCryptographyConfiguration {
                SymmetricCipher = this.SymmetricCipher.CloneSafely(),
                Authentication = this.Authentication.CloneSafely(),
                AuthenticationVerifiedOutput = null,
                KeyConfirmation = this.KeyConfirmation.CloneSafely(),
                KeyConfirmationVerifiedOutput = null,
                KeyDerivation = this.KeyDerivation.CloneSafely()
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
            return Equals((SymmetricManifestCryptographyConfiguration) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = (KeyConfirmation != null ? KeyConfirmation.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^
                           (KeyConfirmationVerifiedOutput != null ? KeyConfirmationVerifiedOutput.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ KeyDerivation.GetHashCode();
                hashCode = (hashCode * 397) ^ SymmetricCipher.GetHashCode();
                hashCode = (hashCode * 397) ^ Authentication.GetHashCode();
                hashCode = (hashCode * 397) ^ AuthenticationVerifiedOutput.GetHashCode();
                return hashCode;
            }
        }
    }
}
