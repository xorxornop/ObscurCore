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

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Configuration for a scheme controlling how payload items 
    ///     are physically laid out (as sequences of bytes) relative to each other.
    /// </summary>
    [ProtoContract]
    public sealed class PayloadConfiguration : IPayloadConfiguration,
        IDataTransferObject, IEquatable<PayloadConfiguration>
    {
        /// <summary>
        ///     Name of the payload layout scheme, e.g. Frameshift.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string SchemeName { get; set; }

        /// <summary>
        ///     Configuration for the scheme.
        /// </summary>
        /// <remarks>
        ///     Format of the configuration is that of the consuming type.
        /// </remarks>
        [ProtoMember(2, IsRequired = false)]
        public byte[] SchemeConfiguration { get; set; }      

        /// <summary>
        ///     Entropy scheme for e.g. selecting the active stream,
        ///     and other payload-scheme-specific states.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public PayloadMuxEntropyScheme EntropyScheme { get; set; }

        /// <summary>
        ///     Configuration for the <see cref="EntropyScheme"/>.
        /// </summary>
        /// <remarks>
        ///     Format of the configuration is that of the consuming type.
        /// </remarks>
        [ProtoMember(4, IsRequired = false)]
        public byte[] EntropySchemeData { get; set; }

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) {
                return false;
            }
            if (ReferenceEquals(this, obj)) {
                return true;
            }
            return obj is PayloadConfiguration && Equals((PayloadConfiguration) obj);
        }

        /// <inheritdoc />
        public bool Equals(PayloadConfiguration other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return String.Equals(SchemeName, other.SchemeName, StringComparison.OrdinalIgnoreCase) &&
                   (SchemeConfiguration == null
                       ? other.SchemeConfiguration == null
                       : SchemeConfiguration.SequenceEqualShortCircuiting(other.SchemeConfiguration)) &&
                   EntropyScheme == other.EntropyScheme &&
                   (EntropySchemeData == null
                       ? other.EntropySchemeData == null
                       : EntropySchemeData.SequenceEqualShortCircuiting(other.EntropySchemeData));
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = SchemeName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ (SchemeConfiguration != null ? SchemeConfiguration.GetHashCodeExt() : 0);
                hashCode = (hashCode * 397) ^ EntropyScheme.GetHashCode();
                hashCode = (hashCode * 397) ^ (EntropySchemeData != null ? EntropySchemeData.GetHashCodeExt() : 0);
                return hashCode;
            }
        }
    }
}
