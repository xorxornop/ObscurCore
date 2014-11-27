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
using System.Collections.Generic;
using ProtoBuf;

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Manifest for a package - payload configuration, contents, etc.
    /// </summary>
    [ProtoContract]
    public sealed class Manifest : IManifest, IDataTransferObject, IEquatable<Manifest>
    {
        /// <summary>
        ///     Creates a new package manifest.
        /// </summary>
        public Manifest()
        {
            PayloadItems = new List<PayloadItem>();
            PayloadConfiguration = new PayloadConfiguration();
        }

        /// <inheritdoc />
        public bool Equals(Manifest other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return PayloadItems.Equals(other.PayloadItems) &&
                   PayloadConfiguration.Equals(other.PayloadConfiguration);
        }

        /// <summary>
        ///     Sequence of payload item descriptors. Order must be preserved for data integrity.
        /// </summary>
        /// <remarks>
        ///     This may be a file system path or other schema.
        ///     <para>
        ///         WARNING: Ordering of this list of items MUST be maintained!
        ///         Failure to ensure this will result in total loss of package contents at unpackaging stage.
        ///     </para>
        /// </remarks>
        [ProtoMember(1, IsRequired = true)]
        public List<PayloadItem> PayloadItems { get; private set; }

        /// <summary>
        ///     Configuration of the payload (how payload items are laid out).
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public PayloadConfiguration PayloadConfiguration { get; set; }

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) {
                return false;
            }
            if (ReferenceEquals(this, obj)) {
                return true;
            }
            return obj.GetType() == GetType() && Equals((Manifest) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = PayloadItems.GetHashCode();
                hashCode = (hashCode * 397) ^ PayloadConfiguration.GetHashCode();
                return hashCode;
            }
        }
    }
}
