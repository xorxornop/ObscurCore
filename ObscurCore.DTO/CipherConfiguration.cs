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
    /// <summary>
    ///     Configuration for CipherStream [en/de]crypting streams.
    /// </summary>
    [ProtoContract]
    public class CipherConfiguration : ICipherConfiguration,
        IDataTransferObject, IEquatable<CipherConfiguration>, ICloneableSafely<CipherConfiguration>
    {
        #region Data relevant to all symmetric ciphers

        /// <summary>
        ///     Category/type of the cipher primitive, e.g. block or stream.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public CipherType Type { get; set; }

        /// <summary>
        ///     Name of the cipher primitive, e.g. AES.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string CipherName { get; set; }

        /// <summary>
        ///     Size of the key being used, in bits.
        /// </summary>
        [ProtoMember(3)]
        public int KeySizeBits { get; set; }

        /// <summary>
        ///     Data that initialises the state of the cipher prior to processing any data.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public byte[] InitialisationVector { get; set; }

        #endregion

        /// <summary>
        ///     Mode of operation used in the cipher, where applicable (block ciphers).
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public string ModeName { get; set; }

        /// <summary>
        ///     Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        ///     true if the current object is equal to the <paramref name="other" /> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals(CipherConfiguration other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return Type.Equals(other.Type) &&
                   String.Equals(CipherName, other.CipherName, StringComparison.OrdinalIgnoreCase) &&
                   KeySizeBits == other.KeySizeBits &&
                   (InitialisationVector == null
                       ? other.InitialisationVector == null
                       : InitialisationVector.SequenceEqualShortCircuiting(other.InitialisationVector)) &&
                   String.Equals(ModeName, other.ModeName, StringComparison.OrdinalIgnoreCase) &&
                   BlockSizeBits == other.BlockSizeBits &&
                   String.Equals(PaddingName, other.PaddingName, StringComparison.OrdinalIgnoreCase);
        }

        #region Block-cipher related

        /// <summary>
        ///     Size of each block of data in bits.
        /// </summary>
        [ProtoMember(6)]
        public int? BlockSizeBits { get; set; }

        /// <summary>
        ///     Scheme utillised to 'pad' blocks to full size where required (block ciphers in some modes).
        /// </summary>
        [ProtoMember(7, IsRequired = false)]
        public string PaddingName { get; set; }

        #endregion

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
            return Equals((CipherConfiguration) obj);
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
                int hashCode = Type.GetHashCode();
                hashCode = (hashCode * 397) ^ CipherName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ KeySizeBits;
                hashCode = (hashCode * 397) ^ (InitialisationVector != null ? InitialisationVector.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ModeName != null ? ModeName.ToLowerInvariant().GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (BlockSizeBits != null ? BlockSizeBits.Value : 0);
                hashCode = (hashCode * 397) ^ (PaddingName != null ? PaddingName.ToLowerInvariant().GetHashCode() : 0);
                return hashCode;
            }
        }

        /// <summary>
        ///     Outputs a summary of the configuration.
        /// </summary>
        public override string ToString()
        {
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}",
                Type, CipherName, KeySizeBits);
        }

        /// <summary>
        ///     Performs deep-copy of configuration. 
        ///     Note: does NOT copy initialisation vector. 
        ///     IV should be new for each cipher configuration.
        /// </summary>
        /// <returns></returns>
        public CipherConfiguration CloneSafely()
        {
            return new CipherConfiguration {
                Type = this.Type,
                CipherName = String.Copy(this.CipherName),
                KeySizeBits = this.KeySizeBits,
                InitialisationVector = null,
                ModeName = (this.ModeName != null ? String.Copy(this.ModeName) : null),
                BlockSizeBits = this.BlockSizeBits,
                PaddingName = (this.PaddingName != null ? String.Copy(this.PaddingName) : null)
            };
        }
    }
}
