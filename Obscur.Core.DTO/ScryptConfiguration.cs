#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using ProtoBuf;

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Configuration for the scrypt key derivation function.
    /// </summary>
    [ProtoContract]
    public struct ScryptConfiguration : IDataTransferObject, IEquatable<ScryptConfiguration>
    {
        /// <summary>
        ///     Number of iterations of hashing to perform.
        ///     Causes the algorithm to take more cumulative time.
        /// </summary>
        /// <remarks>
        ///     General-use cost increase. Use to scale cost/difficulty without changing CPU or memory cost directly, only time.
        /// </remarks>
        [ProtoMember(1, IsRequired = true)]
        public int Iterations { get; set; }

        /// <summary>
        ///     Blocks to operate on. Increases memory cost, as this algorithm is memory-hard.
        /// </summary>
        /// <remarks>
        ///     Use sparingly in constrained environment such as mobile. Scale according to memory advancements.
        /// </remarks>
        [ProtoMember(2, IsRequired = true)]
        public int Blocks { get; set; }

        /// <summary>
        ///     How many co-dependent mix operations must be performed.
        /// </summary>
        /// <remarks>
        ///     Can be run in parallel, hence the name. Increases CPU cost. Scale according to CPU speed advancements.
        /// </remarks>
        [ProtoMember(3, IsRequired = true)]
        public int Parallelism { get; set; }

        #region IEquatable<ScryptConfiguration> Members

        /// <inheritdoc />
        public bool Equals(ScryptConfiguration other)
        {
            return Iterations == other.Iterations && Blocks == other.Blocks && Parallelism == other.Parallelism;
        }

        #endregion

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) {
                return false;
            }
            if (obj.GetType() != GetType()) {
                return false;
            }
            return Equals((ScryptConfiguration) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = Iterations.GetHashCode();
                hashCode = (hashCode * 397) ^ Blocks.GetHashCode();
                hashCode = (hashCode * 397) ^ Parallelism.GetHashCode();
                return hashCode;
            }
        }
    }
}
