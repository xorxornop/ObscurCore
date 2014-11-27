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
    ///     Configuration for the PBKDF2 key derivation function.
    /// </summary>
    [ProtoContract]
    public struct Pbkdf2Configuration : IDataTransferObject, IEquatable<Pbkdf2Configuration>
    {
        /// <summary>
        ///     Hash/digest function to use within HMAC function.
        /// </summary>
        /// <remarks>
        ///     Default is HMAC-SHA256.
        /// </remarks>
        [ProtoMember(1, IsRequired = true)]
        public string FunctionName { get; set; }

        /// <summary>
        ///     Number of times the algorithm will be run sequentially.
        ///     Causes the algorithm to take more cumulative time.
        /// </summary>
        /// <remarks>
        ///     General-use cost increase. Use to scale cost/difficulty without changing CPU or memory cost directly, only time.
        /// </remarks>
        [ProtoMember(2, IsRequired = true)]
        public int Iterations { get; set; }

        /// <inheritdoc />
        public bool Equals(Pbkdf2Configuration other)
        {
            return String.Equals(FunctionName, other.FunctionName) && Iterations == other.Iterations;
        }

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) {
                return false;
            }
            if (obj.GetType() != GetType()) {
                return false;
            }
            return Equals((Pbkdf2Configuration)obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = FunctionName.ToLowerInvariant().GetHashCode();
                hashCode = (hashCode * 397) ^ Iterations.GetHashCode();
                return hashCode;
            }
        }
    }
}
