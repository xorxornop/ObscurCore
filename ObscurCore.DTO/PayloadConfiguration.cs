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
using System.Linq;
using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    /// Configuration of how payload items are physically laid out 
    /// in sequences of bytes relative to each other.
    /// </summary>
    [ProtoContract]
    public sealed class PayloadConfiguration : IPayloadConfiguration, 
        IDataTransferObject, IEquatable<PayloadConfiguration>
    {
        /// <summary>
        /// Name of the payload layout scheme, e.g. Frameshift.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string SchemeName { get; set; }
		
        /// <summary>
        /// Configuration for the scheme.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(2, IsRequired = false)]
        public byte[] SchemeConfiguration { get; set; }
		
        /// <summary>
        /// Name of the PRNG used for selecting the active stream, 
        /// and other scheme-specific states.
        /// </summary>
        [ProtoMember(3, IsRequired = false)]
        public string PrimaryPrngName { get; set; }
		
        /// <summary>
        /// Configuration for the primary PRNG.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(4, IsRequired = false)]
        public byte[] PrimaryPrngConfiguration { get; set; }
		
        ///// <summary>
        ///// Name of the secondary PRNG used for other tasks that the layout scheme may require. 
        ///// </summary>		
        //[ProtoMember(5)]
        //public string SecondaryPrngName { get; set; }
		
        ///// <summary>
        ///// Configuration for the secondary PRNG.
        ///// </summary>
        ///// <remarks>Format of the configuration is that of the consuming type.</remarks>
        //[ProtoMember(6)]
        //public byte[] SecondaryPrngConfiguration { get; set; }

        /// <summary>
        /// Offset at which the payload may be found 
        /// relative to the manifest end in the bytestream. 
        /// This allows for payload I/O frameshifting to increase security.
        /// </summary>
        [ProtoMember(7)]
        public int Offset { get; set; }

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is PayloadConfiguration && Equals((PayloadConfiguration) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (PayloadConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(SchemeName, other.SchemeName) &&
                   (SchemeConfiguration == null ? other.SchemeConfiguration == null : 
                   SchemeConfiguration.SequenceEqual(other.SchemeConfiguration)) && 
                   string.Equals(PrimaryPrngName, other.PrimaryPrngName) &&
                   (PrimaryPrngConfiguration == null ? other.PrimaryPrngConfiguration == null : 
                   PrimaryPrngConfiguration.SequenceEqual(other.PrimaryPrngConfiguration))/* && 
                   string.Equals(SecondaryPRNGName, other.SecondaryPRNGName) && 
                   (SecondaryPRNGConfiguration == null ? other.SecondaryPRNGConfiguration == null : 
                   SecondaryPRNGConfiguration.SequenceEqual(other.SecondaryPRNGConfiguration))*/;
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
                int hashCode = SchemeName.GetHashCode(); // Must have scheme name
                hashCode = (hashCode * 397) ^ (SchemeConfiguration != null ? SchemeConfiguration.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (PrimaryPrngName != null ? PrimaryPrngName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (PrimaryPrngConfiguration != null ? PrimaryPrngConfiguration.GetHashCode() : 0);
                /*
                hashCode = (hashCode * 397) ^ (SecondaryPRNGName != null ? SecondaryPRNGName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (SecondaryPRNGConfiguration != null ? SecondaryPRNGConfiguration.GetHashCode() : 0);
                */
                hashCode = (hashCode * 397) ^ Offset.GetHashCode();
                return hashCode;
            }
        }
    }

    public interface IPayloadConfiguration
    {
        /// <summary>
        /// Name of the payload layout scheme, e.g. Frameshift.
        /// </summary>
        string SchemeName { get; }

        /// <summary>
        /// Configuration for the layout-scheme-specific payload I/O module.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] SchemeConfiguration { get; }

        /// <summary>
        /// Name of the PRNG used to select which item to read/write from/to the payload.
        /// </summary>
        /// <remarks>Convert this name to an enumeration when used internally.</remarks>
        string PrimaryPrngName { get; }

        /// <summary>
        /// Configuration for the stream-selection PRNG.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] PrimaryPrngConfiguration { get; }

        ///// <summary>
        ///// Name of the PRNG used for other tasks that the layout scheme may require. 
        ///// </summary>
        ///// <remarks>
        ///// Convert this name to an enumeration when used internally.
        ///// </remarks>			
        //string SecondaryPrngName { get; }

        ///// <summary>
        ///// Configuration for the auxillary PRNG.
        ///// </summary>
        ///// <remarks>
        ///// Format of the configuration is that of the consuming type.
        ///// </remarks>
        //byte[] SecondaryPrngConfiguration { get; }

        /// <summary>
        /// Offset at which the payload may be found 
        /// relative to the manifest end in the bytestream. 
        /// This allows for payload I/O frameshifting to increase security.
        /// </summary>
        int Offset { get; set; }
    }
}