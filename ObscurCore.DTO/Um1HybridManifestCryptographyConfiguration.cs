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
using System.Linq;
using ProtoBuf;

namespace ObscurCore.DTO
{
    // ***************************************************************************************************************************************************
    // *             This object is not explicitly included in the Manifest supraobject, but may be included in byte-array-serialised form.              *
    // *             They may however incorporate objects in the Manifest superstructure, such as a SymmetricCipherConfiguration or similar.             *
    // ***************************************************************************************************************************************************

    [ProtoContract]
	public class Um1HybridManifestCryptographyConfiguration : IUm1HybridManifestCryptographyConfiguration, 
		IManifestCryptographySchemeConfiguration, IDataTransferObject, IAuthenticatibleClonable<Um1HybridManifestCryptographyConfiguration>,
		IEquatable<Um1HybridManifestCryptographyConfiguration>
    {
		/// <summary>
		/// Configuration for the key confirmation scheme used to validate the existence and 
		/// validity of keying material at respondent's side without disclosing the key itself.
		/// </summary>
		[ProtoMember(1, IsRequired = false)]
		public VerificationFunctionConfiguration KeyConfirmation { get; set; }

		/// <summary>
		/// Output of the key confirmation scheme given correct input data.
		/// </summary>
		[ProtoMember(2, IsRequired = false)]
		public byte[] KeyConfirmationVerifiedOutput { get; set; }

		/// <summary>
		/// Configuration for the scheme used to derive a key from the shared secret.
		/// </summary>
		[ProtoMember(3, IsRequired = true)]
		public KeyDerivationConfiguration KeyDerivation { get; set; }

		/// <summary>
		/// Configuration of the cipher used in encryption of the manifest.
		/// </summary>
		[ProtoMember(4, IsRequired = true)]
		public SymmetricCipherConfiguration SymmetricCipher { get; set; }

		/// <summary>
		/// Configuration for the authentication of the manifest and cipher configuration.
		/// </summary>
		[ProtoMember(5, IsRequired = true)]
		public VerificationFunctionConfiguration Authentication { get; set; }

		/// <summary>
		/// Output of the authentication scheme given correct input data.
		/// </summary>
		[ProtoMember(6, IsRequired = true)]
		public byte[] AuthenticationVerifiedOutput { get; set; }

		/// <summary>
		/// Ephemeral key to be used in UM1 key exchange calculations to produce a shared secret.
		/// </summary>
		[ProtoMember(7, IsRequired = true)]
		public EcKeyConfiguration EphemeralKey { get; set; }

		public Um1HybridManifestCryptographyConfiguration CreateAuthenticatibleClone () {
			return new Um1HybridManifestCryptographyConfiguration {
				KeyConfirmation = this.KeyConfirmation,
				KeyConfirmationVerifiedOutput = this.KeyConfirmationVerifiedOutput,
				KeyDerivation = this.KeyDerivation,
				SymmetricCipher = this.SymmetricCipher,
				Authentication = this.Authentication,
				AuthenticationVerifiedOutput = null,
				EphemeralKey = this.EphemeralKey
			};
		}

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Um1HybridManifestCryptographyConfiguration) obj);
        }

        public bool Equals(Um1HybridManifestCryptographyConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
			return 
				(KeyConfirmation == null ? other.KeyConfirmation == null : KeyConfirmation.Equals(other.KeyConfirmation)) && 
				(KeyConfirmationVerifiedOutput == null ? other.KeyConfirmation == null : 
					KeyConfirmationVerifiedOutput.SequenceEqual(other.KeyConfirmationVerifiedOutput)) && 
				KeyDerivation.Equals(other.KeyDerivation) &&
				SymmetricCipher.Equals(other.SymmetricCipher) &&
				Authentication.Equals(other.Authentication) &&
				AuthenticationVerifiedOutput.SequenceEqual(other.AuthenticationVerifiedOutput) && 
				EphemeralKey.Equals(other.EphemeralKey);
        }

        public override int GetHashCode () {
            unchecked {
				int hashCode = (KeyConfirmation != null ? KeyConfirmation.GetHashCode() : 0);
				hashCode = (hashCode * 397) ^ (KeyConfirmationVerifiedOutput != null ? KeyConfirmationVerifiedOutput.GetHashCode() : 0);
				hashCode = (hashCode * 397) ^ KeyDerivation.GetHashCode(); // Must not be null!
				hashCode = (hashCode * 397) ^ SymmetricCipher.GetHashCode();
				hashCode = (hashCode * 397) ^ Authentication.GetHashCode (); // Must not be null!
				hashCode = (hashCode * 397) ^ AuthenticationVerifiedOutput.GetHashCode (); // Must not be null!
				hashCode = (hashCode * 397) ^ EphemeralKey.GetHashCode(); // Must not be null!
                return hashCode;
            }
        }
    }

    public interface IUm1HybridManifestCryptographyConfiguration 
	{
		/// <summary>
		/// Configuration for the key confirmation scheme used to validate the existence and 
		/// validity of keying material at respondent's side without disclosing the key itself.
		/// </summary>
		VerificationFunctionConfiguration KeyConfirmation { get; }

		/// <summary>
		/// Output of the key confirmation scheme given correct input data.
		/// </summary>
		byte[] KeyConfirmationVerifiedOutput { get; }

		/// <summary>
		/// Configuration for the scheme used to derive a key from the shared secret.
		/// </summary>
		KeyDerivationConfiguration KeyDerivation { get; }

		/// <summary>
		/// Configuration of the cipher used in encryption of the manifest.
		/// </summary>
		SymmetricCipherConfiguration SymmetricCipher { get; }

		/// <summary>
		/// Configuration for the authentication of the manifest and cipher configuration.
		/// </summary>
		VerificationFunctionConfiguration Authentication { get; }

		/// <summary>
		/// Output of the authentication scheme given correct input data.
		/// </summary>
		byte[] AuthenticationVerifiedOutput { get; }

        /// <summary>
        /// Ephemeral key to be used in UM1 key exchange calculations to produce a shared secret.
        /// </summary>
        EcKeyConfiguration EphemeralKey { get; set; }
    }
}