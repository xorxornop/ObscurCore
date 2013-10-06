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
using System.Collections.Generic;
using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    /// Manifest of package - payload configuration, contents, etc.
    /// </summary>
    [ProtoContract]
    public sealed class Manifest : IManifest, IDataTransferObject, IEquatable<Manifest>
    {
        /// <summary>
        /// Sequence of payload item descriptors. Order must be preserved for data integrity. 
        /// </summary>
        /// <remarks>
        /// This may be a file system path or other schema. If used for file system, path seperator is '/' .
        /// Path may be omitted, and use this only for item naming.
        /// <para>WARNING: Ordering of this list of items MUST be maintained!
        /// Failure to ensure this will result in most probably total, non-recoverable loss of package contents at unpackaging stage.</para>
        /// </remarks>
        [ProtoMember(1)]
        public List<PayloadItem> PayloadItems { get; set; }
		
        /// <summary>
        /// Configuration of the payload packaging.
        /// </summary>
        [ProtoMember(2)]
        public PayloadLayoutConfiguration PayloadConfiguration { get; set; }
		
        /// <summary>
        /// Offset at which the payload may be found 
        /// relative to the manifest end in the bytestream. 
        /// This allows for payload I/O frameshifting to increase security.
        /// </summary>
        [ProtoMember(3)]
        public int PayloadOffset { get; set; }

        public override bool Equals (object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Manifest) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (Manifest other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return PayloadItems.Equals(other.PayloadItems) &&
                   PayloadConfiguration.Equals(other.PayloadConfiguration) &&
                   PayloadOffset == other.PayloadOffset;
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
                int hashCode = PayloadItems.GetHashCode();
                hashCode = (hashCode * 397) ^ PayloadConfiguration.GetHashCode();
                hashCode = (hashCode * 397) ^ PayloadOffset;
                return hashCode;
            }
        }
    }

    public interface IManifest
    {
        /// <summary>
        /// Sequence of payload item descriptors. Order must be preserved for data integrity. 
        /// </summary>
        /// <remarks>
        /// This may be a file system path or other schema. If used for file system, path seperator is '/' .
        /// Path may be omitted, and use this only for item naming.
        /// <para>WARNING: Ordering of this list of items MUST be maintained!
        /// Failure to ensure this will result in most probably total, non-recoverable loss of package contents at unpackaging stage.</para>
        /// </remarks>
        List<PayloadItem> PayloadItems { get; }

        /// <summary>
        /// Configuration of the payload packaging.
        /// </summary>
        PayloadLayoutConfiguration PayloadConfiguration { get; }

        /// <summary>
        /// Offset at which the payload may be found 
        /// relative to the manifest end in the bytestream.
        /// </summary>
        int PayloadOffset { get; }
    }
}