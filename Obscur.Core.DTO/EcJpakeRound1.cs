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
    ///     Round 1 in an elliptic curve J-PAKE protocol key agreement. 
    ///     Constitutes a zero-knowledge proof.
    /// </summary>
    [ProtoContract]
    public class ECJpakeRound1 : IDataTransferObject, IEquatable<ECJpakeRound1>
    {
        /// <summary>
        ///     Participant that generated this round's values.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string ParticipantId { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public byte[] GX1 { get; set; }

        [ProtoMember(3, IsRequired = true)]
        public byte[] X1V { get; set; }

        [ProtoMember(4, IsRequired = true)]
        public byte[] X1R { get; set; }

        [ProtoMember(5, IsRequired = true)]
        public byte[] GX2 { get; set; }

        [ProtoMember(6, IsRequired = true)]
        public byte[] X2V { get; set; }

        [ProtoMember(7, IsRequired = true)]
        public byte[] X2R { get; set; }

        /// <inheritdoc />
        public bool Equals(ECJpakeRound1 other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return
                String.Equals(ParticipantId, other.ParticipantId, StringComparison.Ordinal) &&
                GX1.SequenceEqualShortCircuiting(other.GX1) && X1V.SequenceEqualShortCircuiting(other.X1V) &&
                X1R.SequenceEqualShortCircuiting(other.X1R) &&
                GX2.SequenceEqualShortCircuiting(other.GX2) && X2V.SequenceEqualShortCircuiting(other.X2V) &&
                X2R.SequenceEqualShortCircuiting(other.X2R);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = ParticipantId.GetHashCode();
                hashCode = (hashCode * 397) ^ GX1.GetHashCode();
                hashCode = (hashCode * 397) ^ X1V.GetHashCode();
                hashCode = (hashCode * 397) ^ X1R.GetHashCode();
                hashCode = (hashCode * 397) ^ GX2.GetHashCode();
                hashCode = (hashCode * 397) ^ X2V.GetHashCode();
                hashCode = (hashCode * 397) ^ X2R.GetHashCode();
                return hashCode;
            }
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
            return Equals((ECJpakeRound1) obj);
        }
    }
}
