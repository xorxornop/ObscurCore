//
//  Copyright 2014  Matthew Ducker
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
using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
    public class JpakeRound2 : IDataTransferObject
    {
        [ProtoMember(1, IsRequired = true)]
        public string ParticipantId { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public byte[] A { get; set; }

        [ProtoMember(3, IsRequired = true)]
        public byte[] X2sV { get; set; }

        [ProtoMember(4, IsRequired = true)]
        public byte[] X2sR { get; set; }

        public override int GetHashCode()
        {
            unchecked {
                int hashCode = ParticipantId.GetHashCode();
                hashCode = (hashCode * 397) ^ A.GetHashCode();
                hashCode = (hashCode * 397) ^ X2sV.GetHashCode();
                hashCode = (hashCode * 397) ^ X2sR.GetHashCode();
                return hashCode;
            }
        }

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
            return Equals((JpakeRound2) obj);
        }

        public bool Equals(JpakeRound2 other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return String.Equals(ParticipantId, other.ParticipantId, StringComparison.Ordinal) &&
                A.SequenceEqualShortCircuiting(other.A) && X2sV.SequenceEqualShortCircuiting(other.X2sV) &&
                X2sR.SequenceEqualShortCircuiting(other.X2sR);
        }
    }
}
