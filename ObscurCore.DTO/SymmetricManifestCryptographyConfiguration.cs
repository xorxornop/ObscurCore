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

using System.IO;
using ProtoBuf;

namespace ObscurCore.DTO
{
    // ***************************************************************************************************************************************************
    // *             This object is not explicitly included in the Manifest supraobject, but may be included in byte-array-serialised form.              *
    // *             They may however incorporate objects in the Manifest superstructure, such as a SymmetricCipherConfiguration or similar.             *
    // ***************************************************************************************************************************************************

    /// <summary>
    /// Configuration of a symmetric cryptosystem to secure a package manifest.
    /// </summary>
    [ProtoContract]
    public class SymmetricManifestCryptographyConfiguration : IManifestCryptographySchemeConfiguration
    {
        /// <summary>
        /// Encryption configuration for the manifest.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public SymmetricCipherConfiguration SymmetricCipher { get; set; }

        /// <summary>
        /// Key confirmation configuration for the manifest.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public KeyConfirmationConfiguration KeyVerification { get; set; }

        /// <summary>
        /// Key derivation configuration for the manifest.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public KeyDerivationConfiguration KeyDerivation { get; set; }

        public override bool Equals (object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((SymmetricManifestCryptographyConfiguration) obj);
        }

        public bool Equals (SymmetricManifestCryptographyConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return SymmetricCipher.Equals(other.SymmetricCipher) && KeyVerification.Equals(other.KeyVerification) && KeyDerivation.Equals(other.KeyDerivation);
        }

        public override int GetHashCode () {
            if (!IsSuperficiallyValid())
                throw new InvalidDataException("Not a valid manifest cryptography configuration.");
            unchecked {
                int hashCode = SymmetricCipher.GetHashCode();
                hashCode = (hashCode * 397) ^ KeyVerification.GetHashCode();
                hashCode = (hashCode * 397) ^ KeyDerivation.GetHashCode();
                return hashCode;
            }
        }

        public bool IsSuperficiallyValid() { return (SymmetricCipher == null || KeyVerification == null || KeyDerivation == null); }
    }
}