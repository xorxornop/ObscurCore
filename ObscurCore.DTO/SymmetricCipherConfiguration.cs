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
using System.ComponentModel;
using System.Linq;
using System.Text;
using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    /// Configuration for CryptoStream [en/de]crypting streams.
    /// </summary>
    [ProtoContract]
    public class SymmetricCipherConfiguration : ISymmetricCipherConfiguration, 
        IDataTransferObject, IEquatable<SymmetricCipherConfiguration>
    {
        #region Data relevant to all symmetric ciphers

        /// <summary>
		/// Category/type of the cipher primitive, e.g. block or stream.
        /// </summary>
		[ProtoMember(1, IsRequired = true)]
        public SymmetricCipherType Type { get; set; }

        /// <summary>
        /// Name of the cipher primitive, e.g. AES.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string CipherName { get; set; }
		
        /// <summary>
        /// Size of the key being used, in bits.
        /// </summary>
        [ProtoMember(3)]
        public int KeySizeBits { get; set; }

        /// <summary>
        /// Data that initialises the state of the cipher prior to processing any data.
        /// </summary>
		[ProtoMember(4, IsRequired = false)]
        public byte[] IV { get; set; }
        #endregion

        /// <summary>
        /// Mode of operation used in the cipher, where applicable (block ciphers).
        /// </summary>
		[ProtoMember(5, IsRequired = false)]
        public string ModeName { get; set; }

        #region Block-cipher related
        /// <summary>
        /// Size of each block of data in bits.
        /// </summary>
		[ProtoMember(6)]
        public int BlockSizeBits { get; set; }

        /// <summary>
		/// Scheme utillised to 'pad' blocks to full size where required (block ciphers in some modes). 
        /// </summary>
		[ProtoMember(7, IsRequired = false)]
        public string PaddingName { get; set; }
        #endregion

        public override bool Equals (object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((SymmetricCipherConfiguration) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (SymmetricCipherConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Type.Equals(other.Type) &&
                   string.Equals(CipherName, other.CipherName) &&
                   KeySizeBits == other.KeySizeBits &&
                   (IV == null ? other.IV == null : IV.SequenceEqual(other.IV)) &&
                   string.Equals(ModeName, other.ModeName) && BlockSizeBits == other.BlockSizeBits &&
				   string.Equals(PaddingName, other.PaddingName);
        }

        /// <summary>
        /// Serves as a hash function for a particular type. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="T:System.Object"/>.
        /// </returns>
        /// <filterpriority>2</filterpriority>
        public override int GetHashCode () {
            unchecked {
                int hashCode = Type.GetHashCode();
                hashCode = (hashCode * 397) ^ CipherName.GetHashCode(); // Must not be null!
                hashCode = (hashCode * 397) ^ KeySizeBits;
                hashCode = (hashCode * 397) ^ (IV != null ? IV.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ModeName != null ? ModeName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ BlockSizeBits;
                hashCode = (hashCode * 397) ^ (PaddingName != null ? PaddingName.GetHashCode() : 0);
                return hashCode;
            }
        }
		
        /// <summary>
        /// Outputs a summary of the configuration.
        /// </summary>
        public override string ToString () {
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}",
                                 Type, CipherName, KeySizeBits);
        }
    }

    public interface ISymmetricCipherConfiguration
    {
        /// <summary>
        /// Category/type of the cipher primitive, e.g. block, AEAD, or stream. 
        /// AEAD must be specified if using a block cipher in a AEAD mode of operation.
        /// </summary>
        SymmetricCipherType Type { get; }

        /// <summary>
        /// Name of the cipher primitive, e.g. AES.
        /// </summary>
        string CipherName { get; }

        /// <summary>
        /// Size of the key being used, in bits.
        /// </summary>
        int KeySizeBits { get; }

        /// <summary>
        /// Data that initialises the  state of the cipher prior to processing any data.
        /// </summary>
        byte[] IV { get; }

        /// <summary>
        /// Mode of operation used in the cipher, where applicable (block and AEAD ciphers).
        /// </summary>
        string ModeName { get; }

        /// <summary>
        /// Size of each block of data in bits.
        /// </summary>
        int BlockSizeBits { get; }

        /// <summary>
        /// Scheme utillised to 'pad' blocks to full size where required. 
        /// </summary>
        string PaddingName { get; }
    }
}