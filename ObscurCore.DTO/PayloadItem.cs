//
//  Copyright 2013  Matthew Ducker
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
using System.IO;
using ProtoBuf;

//[assembly: InternalsVisibleTo(assemblyName: "ObscurCore")]

namespace ObscurCore.DTO
{
    /// <summary>
    /// Description of an item in the payload.
    /// </summary>
    [ProtoContract]
    public sealed class PayloadItem : IStreamBinding, IEquatable<PayloadItem>, IDisposable
    {
        public PayloadItem ()
        {
            Identifier = Guid.NewGuid ();
        }

        internal PayloadItem (out Guid identifier) : this()
        {
            identifier = this.Identifier;
        }

        internal PayloadItem (Func<Stream> streamBinder, out Guid identifier) : this(out identifier) {
            SetStreamBinding (streamBinder);
        }

        /// <summary>
        /// Identifier used for stream binding.
        /// </summary>
        /// <remarks>
        /// Strictly for library internal use only. Do not export this information outside the system.
        /// </remarks> 
        [ProtoIgnore]
        public Guid Identifier { get; private set; }

		[ProtoIgnore]
        private Lazy<Stream> _stream = null;

		public void SetStreamBinding(Func<Stream> streamBinding) { _stream = new Lazy<Stream> (streamBinding); }

        [ProtoIgnore]
        public Stream StreamBinding { get { return _stream.Value; } }

        /// <summary>
        /// State of stream binding - whether stream is active, or in quiescent (lazy) state. Not the same as StreamHasBinding property.
        /// </summary>
        [ProtoIgnore]
        public bool StreamInitialised { get { return _stream.IsValueCreated; } }

        /// <summary>
        /// State of stream binding - whether it has a lazy binding (can be activated), or none at all (activation is impossible; null reference).
        /// </summary>
        [ProtoIgnore]
        public bool StreamHasBinding { get { return _stream != null; } }

        /// <summary>
        /// Item handling behaviour category. 
        /// Key actions should be handled differently from the others.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        public PayloadItemTypes Type { get; set; }
		
        /// <summary>
        /// Path of the stored data. 'Path' syntax may correspond to a key-value collection, filesystem, or other hierarchal schema. 
        /// Syntax uses '/' to seperate stores/directories. Item names may or may not have extensions (if files/binary-data-type).
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        public string RelativePath { get; set; }

        /// <summary>
        /// Length of the item inside of the payload, excluding any additional length imparted by the payload layout module.
        /// </summary>
        [ProtoMember(3)]
        public long InternalLength { get; set; }

        /// <summary>
        /// Length of the item outside of of the payload (unmodified, unpackaged, as intended to be extracted to).
        /// </summary>
        [ProtoMember(4)]
        public long ExternalLength { get; set; }

        /// <summary>
        /// Compression configuration for this payload item.
        /// </summary>
        [ProtoMember(5, IsRequired = true)]
        public CompressionConfiguration Compression { get; set; }
		
        /// <summary>
        /// Encryption configuration for this payload item.
        /// </summary>
        [ProtoMember(6, IsRequired = true)]
        public SymmetricCipherConfiguration Encryption { get; set; }
		
        /// <summary>
        /// Key confirmation configuration for this payload item.
        /// </summary>
        [ProtoMember(7, IsRequired = false)]
        public KeyConfirmationConfiguration KeyVerification { get; set; }

        /// <summary>
        /// Key derivation configuration for this payload item.
        /// </summary>
        [ProtoMember(8, IsRequired = false)]
        public KeyDerivationConfiguration KeyDerivation { get; set; }

        public override bool Equals (object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((PayloadItem) obj);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals (PayloadItem other) {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Type.Equals(other.Type) &&
                   string.Equals(RelativePath, other.RelativePath,
                                 Type == PayloadItemTypes.Binary ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
                   InternalLength == other.InternalLength && ExternalLength == other.ExternalLength && Encryption.Equals(other.Encryption) && 
                   Compression.Equals(other.Compression) && 
                   (KeyVerification == null ? other.KeyVerification == null : KeyVerification.Equals(other.KeyVerification)) &&
                   KeyDerivation == null ? other.KeyDerivation == null : KeyDerivation.Equals((other.KeyDerivation));
        }

        /// <summary>
        /// Serves as a hash function for a particular type. 
        /// </summary>
        /// <returns>
        /// A hash code for the current <see cref="T:System.Object"/>.
        /// </returns>
        /// <filterpriority>2</filterpriority>
        public override int GetHashCode () {
            unchecked {
                int hashCode = Type.GetHashCode();
                hashCode = (hashCode * 397) ^ (Type == PayloadItemTypes.Binary ? 
                                                                                   StringComparer.OrdinalIgnoreCase.GetHashCode(RelativePath) : StringComparer.Ordinal.GetHashCode(RelativePath));
                hashCode = (hashCode * 397) ^ InternalLength.GetHashCode();
                hashCode = (hashCode * 397) ^ ExternalLength.GetHashCode();
                hashCode = (hashCode * 397) ^ (Encryption != null ? Encryption.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Compression != null ? Compression.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (KeyVerification != null ? KeyVerification.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (KeyDerivation != null ? KeyDerivation.GetHashCode() : 0);
                return hashCode;
            }
        }

        public void Dispose () {
            if (_stream.IsValueCreated) {
                _stream.Value.Close();
            }
        }
    }

	/// <summary>
	/// Interface for stream bindings that payload layout I/O modules accept as input.
	/// </summary>
	public interface IStreamBinding
	{
		/// <summary>
		/// Identifier used for stream binding for internal system use only. 
		/// Not exported or useful outside of local data environment.
		/// </summary>
		Guid Identifier { get; }
		
		
		Stream StreamBinding { get; }
		
		/// <summary>
		/// Initialisation state of <see cref="StreamBinding"/> - whether stream is active, or in quiescent ("lazy") state. 
		/// Not the same as <see cref="StreamHasBinding"/>!
		/// </summary>
		bool StreamInitialised { get; }
		
		/// <summary>
		/// State of <see cref="StreamBinding"/> - whether it has a lazy binding (can be activated), 
		/// or none at all (activation is impossible; null reference).
		/// </summary>
		bool StreamHasBinding { get; }
		
		long InternalLength { get; set; }
        long ExternalLength { get; set; }
	}
}