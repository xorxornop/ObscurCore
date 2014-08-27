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
    ///     Key derivation function (KDF) configuration.
    /// </summary>
    [ProtoContract]
    public class KeyDerivationConfiguration : IKeyDerivationConfiguration, IDataTransferObject, 
        ICloneableSafely<KeyDerivationConfiguration>, IEquatable<KeyDerivationConfiguration>
    {
        /// <inheritdoc />
        public bool Equals(KeyDerivationConfiguration other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return Salt.SequenceEqualShortCircuiting(other.Salt) &&
                   String.Equals(FunctionName, other.FunctionName, StringComparison.OrdinalIgnoreCase) &&
                   (FunctionConfiguration == null
                       ? other.FunctionConfiguration == null
                       : FunctionConfiguration.SequenceEqualShortCircuiting(other.FunctionConfiguration));
        }

        /// <summary>
        ///     Name of the key derivation function (KDF).
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string FunctionName { get; set; }

        /// <summary>
        ///     Configuration for the key derivation function.
        /// </summary>
        /// <remarks>
        ///     Format of the configuration is that of the consuming type.
        /// </remarks>
        [ProtoMember(2, IsRequired = false)]
        public byte[] FunctionConfiguration { get; set; }

        /// <summary>
        ///     Data used by KDF to extend and/or strengthen base key material.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] Salt { get; set; }

        /// <inheritdoc />
        public KeyDerivationConfiguration CloneSafely()
        {
            return new KeyDerivationConfiguration {
                FunctionName = String.Copy(this.FunctionName),
                FunctionConfiguration = this.FunctionConfiguration.DeepCopy(),
                Salt = null
            };
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
            return Equals((KeyDerivationConfiguration) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = Salt.GetHashCode();
                hashCode = (hashCode * 397) ^ FunctionName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ (FunctionConfiguration != null ? FunctionConfiguration.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
