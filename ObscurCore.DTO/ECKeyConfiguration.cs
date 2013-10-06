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
    public class ECKeyConfiguration : IDataTransferObject, IEquatable<ECKeyConfiguration>
    {
        /// <summary>
        /// Name of the curve provider. Used to look up relevant domain parameters to interpret the encoded key.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string CurveProviderName { get; set; }
		
        /// <summary>
        /// Name of the elliptic curve in the provider's selection.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string CurveName { get; set; }
		
        /// <summary>
        /// Byte-array-encoded form of the key.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] EncodedKey { get; set; }

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((ECKeyConfiguration) obj);
        }
		
        public bool Equals(ECKeyConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            if(!IsSuperficiallyValid()) 
                throw new InvalidDataException("Not a valid key configuration.");
            return string.Equals(CurveProviderName, other.CurveProviderName) && string.Equals(CurveName, other.CurveName) &&
                   EncodedKey.SequenceEqual(other.EncodedKey);
        }
		
        public override int GetHashCode () {
            if (!IsSuperficiallyValid())
                throw new InvalidDataException("Not a valid key configuration.");
            unchecked {
                int hashCode = CurveProviderName.GetHashCode(); // Must not be null!
                hashCode = (hashCode * 397) ^ CurveName.GetHashCode(); // Must not be null!
                hashCode = (hashCode * 397) ^ EncodedKey.GetHashCode(); // Must not be null! 
                return hashCode;
            }
        }

        public bool IsSuperficiallyValid() {
            return String.IsNullOrEmpty(CurveProviderName) || String.IsNullOrEmpty(CurveName) || EncodedKey == null;
        }
    }
}