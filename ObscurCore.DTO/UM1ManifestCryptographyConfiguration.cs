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
    // ***************************************************************************************************************************************************
    // *             This object is not explicitly included in the Manifest supraobject, but may be included in byte-array-serialised form.              *
    // *             They may however incorporate objects in the Manifest superstructure, such as a SymmetricCipherConfiguration or similar.             *
    // ***************************************************************************************************************************************************

    [ProtoContract]
    public class UM1ManifestCryptographyConfiguration : IManifestCryptographySchemeConfiguration, 
        IDataTransferObject, IEquatable<UM1ManifestCryptographyConfiguration>
    {
		/// <summary>
		/// Configuration of the cipher used in encryption of the manifest.
		/// </summary>
		[ProtoMember(1, IsRequired = true)]
		public SymmetricCipherConfiguration SymmetricCipher { get; set; }

		/// <summary>
		/// Configuration for the authentication of the manifest and cipher configuration.
		/// </summary>
		[ProtoMember(2, IsRequired = true)]
		public VerificationFunctionConfiguration Authentication { get; set; }

		/// <summary>
		/// Output of the key confirmation scheme given correct input data.
		/// </summary>
		[ProtoMember(3, IsRequired = true)]
		public byte[] AuthenticationVerifiedOutput { get; set; }

		/// <summary>
		/// Configuration for the key confirmation scheme used to validate the existence and 
		/// validity of keying material at respondent's side without disclosing the key itself.
		/// </summary>
		[ProtoMember(4, IsRequired = false)]
		public VerificationFunctionConfiguration KeyConfirmation { get; set; }

		/// <summary>
		/// Output of the key confirmation scheme given correct input data.
		/// </summary>
		[ProtoMember(5, IsRequired = false)]
		public byte[] KeyConfirmationVerifiedOutput { get; set; }

		/// <summary>
		/// Configuration for the scheme used to derive a key from the shared secret.
		/// </summary>
		[ProtoMember(6, IsRequired = true)]
		public KeyDerivationConfiguration KeyDerivation { get; set; }

		/// <summary>
		/// Ephemeral key to be used in UM1 key exchange calculations to produce a shared secret.
		/// </summary>
		[ProtoMember(7, IsRequired = true)]
		public EcKeyConfiguration EphemeralKey { get; set; }

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((UM1ManifestCryptographyConfiguration) obj);
        }

        public bool Equals(UM1ManifestCryptographyConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return SymmetricCipher.Equals(other.SymmetricCipher) 
				&& Authentication.Equals(other.Authentication) && 
				(KeyConfirmation == null ? other.KeyConfirmation == null : KeyConfirmation.Equals(other.KeyConfirmation)) 
                && KeyDerivation.Equals(other.KeyDerivation) && EphemeralKey.Equals(other.EphemeralKey);
        }

        public override int GetHashCode () {
            unchecked {
                int hashCode = SymmetricCipher.GetHashCode(); // Must not be null!
				hashCode = (hashCode * 397) ^ Authentication.GetHashCode (); // Must not be null!
                hashCode = (hashCode * 397) ^ (KeyConfirmation != null ? KeyConfirmation.GetHashCode() : 0); 
                hashCode = (hashCode * 397) ^ KeyDerivation.GetHashCode(); // Must not be null!
                hashCode = (hashCode * 397) ^ EphemeralKey.GetHashCode(); // Must not be null!
                return hashCode;
            }
        }
    }

    public interface IUM1ManifestCryptographyConfiguration {
        /// <summary>
        /// Configuration for the symmetric cipher to use with the key derived from the shared secret.
        /// </summary>
        SymmetricCipherConfiguration SymmetricCipher { get; }

		/// <summary>
		/// Configuration for the authentication of the manifest and cipher configuration.
		/// </summary>
		VerificationFunctionConfiguration Authentication { get; }

        /// <summary>
        /// Key confirmation configuration for the manifest. 
        /// Used to validate the existence and validity of keying material 
        /// at the respondent's side without disclosing the key itself.
        /// </summary>
        VerificationFunctionConfiguration KeyConfirmation { get; }

        /// <summary>
        /// Configuration for the scheme used to derive a key from the shared secret.
        /// </summary>
        KeyDerivationConfiguration KeyDerivation { get; }

        /// <summary>
        /// Ephemeral key to be used in UM1 key exchange calculations to produce a shared secret.
        /// </summary>
        EcKeyConfiguration EphemeralKey { get; set; }
    }
}