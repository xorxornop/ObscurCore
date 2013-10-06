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
        [ProtoMember(1, IsRequired = true), DefaultValue(SymmetricCipherType.None)]
        public SymmetricCipherType Type { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public string CipherName { get; set; }
		
        /// <summary>
        /// Size of the key being used, in bits.
        /// </summary>
        [ProtoMember(3)]
        public int KeySize { get; set; }
		
        /// <summary>
        /// One-time key to use in place of one derived using a supplied KDF configuration using the supplied 
        /// salt and a key from a local security context's keystore.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        public byte[] Key { get; set; }

        /// <summary>
        /// Data that initialises the state of the cipher prior to processing any data.
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        public byte[] IV { get; set; }
        #endregion

        /// <summary>
        /// Mode of operation used in the cipher, where applicable (block and AEAD ciphers).
        /// </summary>
        [ProtoMember(6, IsRequired = false)]
        public string ModeName { get; set; }

        #region Block-cipher related
        /// <summary>
        /// Size of each block of data in bits.
        /// </summary>
        [ProtoMember(7)]
        public int BlockSize { get; set; }

        /// <summary>
        /// Scheme utillised to 'pad' blocks to full size where required. 
        /// </summary>
        [ProtoMember(8, IsRequired = false)]
        public string PaddingName { get; set; }
        #endregion

        #region AEAD-related
        /// <summary>
        /// Size of the Message Authentication Code (MAC) hash in bits.
        /// </summary>
        [ProtoMember(9)]
        public int MACSize { get; set; }

        /// <summary>
        /// Data concatenated with the ciphertext that is authenticated, but not encrypted (authenticity without privacy).
        /// </summary>
        [ProtoMember(10, IsRequired = false)]
        public byte[] AssociatedData { get; set; }
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
                   KeySize == other.KeySize &&
					(Key == null ? other.Key == null : Key.SequenceEqual(other.Key)) &&
                   (IV == null ? other.IV == null : IV.SequenceEqual(other.IV)) &&
                   string.Equals(ModeName, other.ModeName) && BlockSize == other.BlockSize && string.Equals(PaddingName, other.PaddingName) &&
                   MACSize == other.MACSize &&
                   (AssociatedData == null ? other.AssociatedData == null : AssociatedData.SequenceEqual(other.AssociatedData));
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
                hashCode = (hashCode * 397) ^ KeySize;
				hashCode = (hashCode * 397) ^ (Key != null ? Key.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (IV != null ? IV.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ModeName != null ? ModeName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ BlockSize;
                hashCode = (hashCode * 397) ^ (PaddingName != null ? PaddingName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ MACSize;
                hashCode = (hashCode * 397) ^ (AssociatedData != null ? AssociatedData.GetHashCode() : 0);
                return hashCode;
            }
        }
		
        /// <summary>
        /// Outputs a summary of the configuration.
        /// </summary>
        public override string ToString () {
            return String.Format("Cipher type: {0}\nName: {1}\nKey size (bits): {2}",
                                 Type, CipherName, KeySize);
        }
		
        
    }

    public interface ISymmetricCipherConfiguration
    {
        SymmetricCipherType Type { get; }

        string CipherName { get; }

        /// <summary>
        /// Size of the key being used, in bits.
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// One-time key to use in place of one derived using a supplied KDF configuration 
        /// using the supplied salt and a key from a local keystore. If used, no KDF is used or should be specified.
        /// </summary>
        /// <value>The ephemeral key.</value>
		byte[] Key { get; }

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
        int BlockSize { get; }

        /// <summary>
        /// Scheme utillised to 'pad' blocks to full size where required. 
        /// </summary>
        string PaddingName { get; }

        /// <summary>
        /// Size of the Message Authentication Code (MAC) hash in bits.
        /// </summary>
        int MACSize { get; }

        /// <summary>
        /// Data concatenated with the ciphertext that is authenticated, but not encrypted (authenticity without privacy).
        /// </summary>
        byte[] AssociatedData { get; }
    }
}