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
    /// in sequences of bytes, relative to each other.
    /// </summary>
    [ProtoContract]
    public sealed class PayloadLayoutConfiguration : IPayloadLayoutConfiguration, IEquatable<PayloadLayoutConfiguration>
    {
        [ProtoMember(1)]
        public string SchemeName { get; set; }
		
        /// <summary>
        /// Configuration for the layout-scheme-specific payload I/O module.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(2)]
        public byte[] SchemeConfiguration { get; set; }
		
        /// <summary>
        /// Name of the PRNG used to select which item to read/write from/to the payload.
        /// </summary>
        [ProtoMember(3)]
        public string StreamPRNGName { get; set; }
		
        /// <summary>
        /// Configuration for the stream-selection PRNG.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(4)]
        public byte[] StreamPRNGConfiguration { get; set; }
		
        /// <summary>
        /// Name of the secondary PRNG used for other tasks that the layout scheme may require. 
        /// </summary>		
        [ProtoMember(5)]
        public string SecondaryPRNGName { get; set; }
		
        /// <summary>
        /// Configuration for the secondary PRNG.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(6)]
        public byte[] SecondaryPRNGConfiguration { get; set; }

        /// <summary>
        /// Name of the tertiary PRNG used for other tasks that the layout scheme may require. 
        /// </summary>		
        [ProtoMember(7)]
        public string TertiaryPRNGName { get; set; }
		
        /// <summary>
        /// Configuration for the tertiary PRNG.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(8)]
        public byte[] TertiaryPRNGConfiguration { get; set; }

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is PayloadLayoutConfiguration && Equals((PayloadLayoutConfiguration) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (PayloadLayoutConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(SchemeName, other.SchemeName) &&
                   (SchemeConfiguration == null ? other.SchemeConfiguration == null : 
                   SchemeConfiguration.SequenceEqual(other.SchemeConfiguration)) && 
                   string.Equals(StreamPRNGName, other.StreamPRNGName) &&
                   (StreamPRNGConfiguration == null ? other.StreamPRNGConfiguration == null : 
                   StreamPRNGConfiguration.SequenceEqual(other.StreamPRNGConfiguration)) && 
                   string.Equals(SecondaryPRNGName, other.SecondaryPRNGName) && 
                   (SecondaryPRNGConfiguration == null ? other.SecondaryPRNGConfiguration == null : 
                   SecondaryPRNGConfiguration.SequenceEqual(other.SecondaryPRNGConfiguration)) &&
                   string.Equals(TertiaryPRNGName, other.TertiaryPRNGName) && 
                   (TertiaryPRNGConfiguration == null ? other.TertiaryPRNGConfiguration == null : 
                   TertiaryPRNGConfiguration.SequenceEqual(other.TertiaryPRNGConfiguration));
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
                hashCode = (hashCode * 397) ^ (StreamPRNGName != null ? StreamPRNGName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (StreamPRNGConfiguration != null ? StreamPRNGConfiguration.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (SecondaryPRNGName != null ? SecondaryPRNGName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (SecondaryPRNGConfiguration != null ? SecondaryPRNGConfiguration.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (TertiaryPRNGName != null ? TertiaryPRNGName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (TertiaryPRNGConfiguration != null ? TertiaryPRNGConfiguration.GetHashCode() : 0);
                return hashCode;
            }
        }
    }

    public interface IPayloadLayoutConfiguration
    {
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
        string StreamPRNGName { get; }

        /// <summary>
        /// Configuration for the stream-selection PRNG.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] StreamPRNGConfiguration { get; }

        /// <summary>
        /// Name of the PRNG used for other tasks that the layout scheme may require. 
        /// </summary>
        /// <remarks>
        /// Convert this name to an enumeration when used internally.
        /// <para>
        /// These must take place in a deterministic, repeatable order, PRNG nonwithstanding - 
        /// if there is multiple consumers of this one random number source, or multiple states such a 
        /// consumer may be in, the order of invocation or consumption must be deterministic/repeatable.
        /// </para>
        /// </remarks>			
        string SecondaryPRNGName { get; }

        /// <summary>
        /// Configuration for the auxillary PRNG.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] SecondaryPRNGConfiguration { get; }
    }
}