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
    ///     Round 3 in a J-PAKE protocol key agreement. 
    ///     Constitutes a key confirmation.
    /// </summary>
    [ProtoContract]
    public class JpakeRound3 : IDataTransferObject, IEquatable<JpakeRound3>
    {
        /// <summary>
        ///     Participant that generated this round's values.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public string ParticipantId { get; set; }

        /// <summary>
        ///     Output of the key confirmation scheme given correct input data.
        ///     Scheme is always HMAC-SHA256.
        /// </summary>
        [ProtoMember(3, IsRequired = true)]
        public byte[] VerifiedOutput { get; set; }

        /// <inheritdoc />
        public bool Equals(JpakeRound3 other)
        {
            if (ReferenceEquals(null, other)) {
                return false;
            }
            if (ReferenceEquals(this, other)) {
                return true;
            }
            return
                String.Equals(ParticipantId, other.ParticipantId, StringComparison.Ordinal) &&
                VerifiedOutput.SequenceEqualShortCircuiting(other.VerifiedOutput);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            unchecked {
                int hashCode = ParticipantId.GetHashCode();
                hashCode = (hashCode * 397) ^ VerifiedOutput.GetHashCode();
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
            return Equals((JpakeRound3) obj);
        }
    }
}
