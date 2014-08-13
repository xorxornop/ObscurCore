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
    ///     Configuration object for a CSPRNG based on a stream cipher.
    /// </summary>
    [ProtoContract]
    public class StreamCipherCsprngConfiguration : IDataTransferObject, IEquatable<StreamCipherCsprngConfiguration>
    {
        /// <summary>
        ///     Name of the stream cipher primitive, e.g. Salsa20.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string CipherName { get; set; }

        /// <summary>
        ///     Cryptographic key to configure the cipher primitive with.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public byte[] Key { get; set; }

        /// <summary>
        ///     Cryptographic nonce to initialise the cipher primitive with.
        /// </summary>
        [ProtoMember(3, IsRequired = false)]
        public byte[] Nonce { get; set; }

        /// <inheritdoc />
        public bool Equals(StreamCipherCsprngConfiguration other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return String.Equals(CipherName, other.CipherName, StringComparison.OrdinalIgnoreCase) &&
                   (Key == null ? other.Key == null : Key.SequenceEqualShortCircuiting(other.Key)) &&
                   (Nonce == null ? other.Nonce == null : Nonce.SequenceEqualShortCircuiting(other.Nonce));
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
            return Equals((StreamCipherCsprngConfiguration)obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = CipherName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ (Key != null ? Key.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Nonce != null ? Nonce.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
