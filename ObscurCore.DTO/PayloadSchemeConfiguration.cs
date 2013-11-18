using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
    public class PayloadSchemeConfiguration : IDataTransferObject, IEquatable<PayloadSchemeConfiguration>, IPayloadSchemeConfiguration
    {
        [ProtoMember(1, IsRequired = false)]
        public int Minimum { get; set; }
		
        [ProtoMember(2, IsRequired = false)]
        public int Maximum { get; set; }

         /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals(PayloadSchemeConfiguration other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Minimum == other.Minimum && Maximum.Equals(other.Maximum);
        }

        /// <summary>
        /// Determines whether the specified <see cref="T:System.Object"/> is equal to the current <see cref="T:System.Object"/>.
        /// </summary>
        /// <returns>
        /// true if the specified object  is equal to the current object; otherwise, false.
        /// </returns>
        /// <param name="obj">The object to compare with the current object. </param>
        public override bool Equals(object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != typeof (PayloadSchemeConfiguration)) return false;
            return Equals((PayloadSchemeConfiguration) obj);
        }

        /// <summary>
        /// Serves as a hash function for a particular type. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="T:System.Object"/>.
        /// </returns>
        public override int GetHashCode() {
            unchecked {
                return (Minimum*397) ^ Maximum.GetHashCode();
            }
        }
    }

    public interface IPayloadSchemeConfiguration {
        [ProtoMember(1, IsRequired = false)]
        int Minimum { get; set; }

        [ProtoMember(2, IsRequired = false)]
        int Maximum { get; set; }
    }
}
