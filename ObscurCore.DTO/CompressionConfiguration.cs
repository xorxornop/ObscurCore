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
    /// Configuration for CompressoStream [de]compressing streams.
    /// </summary>
    [ProtoContract]
    public class CompressionConfiguration : ICompressionConfiguration, IEquatable<CompressionConfiguration>
    {
        /// <summary>
        /// The compression algorithm used.
        /// </summary>
        /// <remarks>Convert this name to an enumeration when used internally.</remarks>
        [ProtoMember(1)]
        public string AlgorithmName { get; set; }
		
        [ProtoMember(2)]
        public byte[] AlgorithmConfiguration { get; set; }

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((CompressionConfiguration) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (CompressionConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals (AlgorithmName, other.AlgorithmName) &&
                   (AlgorithmConfiguration == null ? other.AlgorithmConfiguration == null : AlgorithmConfiguration.SequenceEqual(other.AlgorithmConfiguration));
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
                return (AlgorithmName.GetHashCode() * 397) ^ (AlgorithmConfiguration != null ? AlgorithmConfiguration.GetHashCode() : 0);
            }
        }
    }

    public interface ICompressionConfiguration
    {
        /// <summary>
        /// The compression algorithm used.
        /// </summary>
        /// <remarks>Convert this name to an enumeration when used internally.</remarks>
        string AlgorithmName { get; }

        byte[] AlgorithmConfiguration { get; }
    }
}