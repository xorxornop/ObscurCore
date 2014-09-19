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

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Configuration of a numerical range.
    /// </summary>
    [ProtoContract]
    public struct RangeConfiguration : IDataTransferObject, IEquatable<RangeConfiguration>
    {
        /// <summary>
        ///     Minimum value in the range, inclusive.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public int Minimum { get; set; }

        /// <summary>
        ///     Maximum value in the range, inclusive.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public int Maximum { get; set; }

        #region IEquatable<RangeConfiguration> Members

        /// <inheritdoc />
        public bool Equals(RangeConfiguration other)
        {
            return Minimum == other.Minimum && Maximum.Equals(other.Maximum);
        }

        #endregion

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) {
                return false;
            }
            if (obj.GetType() != typeof (RangeConfiguration)) {
                return false;
            }
            return Equals((RangeConfiguration) obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                return (Minimum * 397) ^ Maximum.GetHashCode();
            }
        }
    }
}
