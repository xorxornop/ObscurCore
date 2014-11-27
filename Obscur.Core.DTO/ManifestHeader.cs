#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using ProtoBuf;

namespace Obscur.Core.DTO
{

    /// <summary>
    ///     Header for a <see cref="Manifest" />.
    /// </summary>
    [ProtoContract]
    public class ManifestHeader : IDataTransferObject, IEquatable<ManifestHeader>, IManifestHeader
    {
        #region IEquatable<ManifestHeader> Members

        /// <inheritdoc />
        public bool Equals(ManifestHeader other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return FormatVersion == other.FormatVersion &&
                   CryptographyScheme == other.CryptographyScheme &&
                   (CryptographySchemeConfiguration == null
                       ? other.CryptographySchemeConfiguration == null
                       : CryptographySchemeConfiguration.SequenceEqualShortCircuiting(
                           other.CryptographySchemeConfiguration));
        }

        #endregion

        #region IManifestHeader Members

        /// <summary>
        ///     Format version of the associated <see cref="Manifest" /> object.
        ///     Used to denote breaking changes that may cause incompatibility.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public int FormatVersion { get; set; }

        /// <summary>
        ///     The cryptographic scheme used to secure the manifest.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public ManifestCryptographyScheme CryptographyScheme { get; set; }

        /// <summary>
        ///     Configuration of the cryptographic scheme used to secure the Manifest.
        /// </summary>
        /// <remarks>
        ///     Format of the configuration is that of the consuming type.
        /// </remarks>
        [ProtoMember(3, IsRequired = false)]
        public byte[] CryptographySchemeConfiguration { get; set; }

        #endregion

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
            return Equals((ManifestHeader) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = FormatVersion.GetHashCode();
                hashCode = (hashCode * 397) ^ CryptographyScheme.GetHashCode();
                hashCode = (hashCode * 397) ^
                           (CryptographySchemeConfiguration != null ? CryptographySchemeConfiguration.GetHashCodeExt() : 0);
                return hashCode;
            }
        }
    }
}
