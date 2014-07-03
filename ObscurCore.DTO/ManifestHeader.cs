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
using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
    public class ManifestHeader : IDataTransferObject, IEquatable<ManifestHeader>, IManifestHeader
    {
        /// <summary>
        ///     Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        ///     true if the current object is equal to the <paramref name="other" /> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals(ManifestHeader other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return FormatVersion == other.FormatVersion && UseCompression == other.UseCompression &&
                   String.Equals(CryptographySchemeName, other.CryptographySchemeName,
                       StringComparison.OrdinalIgnoreCase) &&
                   (CryptographySchemeConfiguration == null
                       ? other.CryptographySchemeConfiguration == null
                       : CryptographySchemeConfiguration.SequenceEqualShortCircuiting(
                           other.CryptographySchemeConfiguration));
        }

        /// <summary>
        ///     Format version of the following Manifest object.
        ///     Used to denote breaking changes that may cause incompatibility.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public int FormatVersion { get; set; }

        /// <summary>
        ///     Whether to use fast LZ4 compression to reduce the size of the manifest.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public bool UseCompression { get; set; }

        /// <summary>
        ///     Name of the cryptographic scheme used to secure the Manifest.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public string CryptographySchemeName { get; set; }

        /// <summary>
        ///     Configuration of the cryptographic scheme used to secure the Manifest.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(4, IsRequired = false)]
        public byte[] CryptographySchemeConfiguration { get; set; }

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

        /// <summary>
        ///     Serves as a hash function for a particular type.
        /// </summary>
        /// <returns>
        ///     A hash code for the current <see cref="T:System.Object" />.
        /// </returns>
        /// <filterpriority>2</filterpriority>
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = FormatVersion.GetHashCode();
                hashCode = (hashCode * 397) ^ UseCompression.GetHashCode();
                hashCode = (hashCode * 397) ^ CryptographySchemeName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ (CryptographySchemeConfiguration != null ? CryptographySchemeConfiguration.GetHashCode() : 0);
                return hashCode;
            }
        }
    }

    public interface IManifestHeader
    {
        /// <summary>
        ///     Format version of the following Manifest object.
        ///     Used to denote breaking changes that may cause incompatibility.
        /// </summary>
        int FormatVersion { get; }

        /// <summary>
        ///     Whether to use fast LZ4 compression to reduce the size of the manifest.
        /// </summary>
        bool UseCompression { get; set; }

        /// <summary>
        ///     Name of the cryptographic scheme used to secure the Manifest.
        /// </summary>
        string CryptographySchemeName { get; }

        /// <summary>
        ///     Configuration of the cryptographic scheme used to secure the Manifest.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] CryptographySchemeConfiguration { get; }
    }
}
