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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.IO;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.EllipticCurve;
using ObscurCore.Extensions.Enumerations;
using ObscurCore.Extensions.Streams;
using ObscurCore.Extensions.Generic;
using ObscurCore.Packaging;
using ProtoBuf;

namespace ObscurCore
{
    public static partial class StratCom
    {
        private const int InitialSeedSize = 64; // bytes
        public static readonly SecureRandom EntropySource = SecureRandom.GetInstance("SHA256PRNG");

        internal readonly static DTOSerialiser Serialiser = new DTOSerialiser();

        
        
        

        static StratCom() {
            EntropySource.SetSeed(SecureRandom.GetSeed(InitialSeedSize));
            EntropySource.SetSeed(Encoding.UTF8.GetBytes(Thread.CurrentThread.Name));
        }

        /// <summary>
		/// Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO namespace).
		/// </summary>
		/// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
		public static MemoryStream SerialiseDTO(object obj, bool lengthPrefix = false) {
		    var type = obj.GetType();
            if (!Serialiser.CanSerializeContractType(type)) {
                throw new ArgumentException("Cannot serialise - requested object does not have a serialisation contract for its type.", "obj");
            }
            var ms = new MemoryStream();
            if (lengthPrefix) {
                Serialiser.SerializeWithLengthPrefix(ms, obj, type, PrefixStyle.Base128, 0);
            } else {
                Serialiser.Serialize(ms, obj);
            }
		    return ms;
		}

        /// <summary>
		/// Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO namespace).
		/// </summary>
		/// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
		public static T DeserialiseDTO<T>(byte[] objectBytes, bool lengthPrefix = false) {
            if (!Serialiser.CanSerializeContractType(typeof(T))) {
                throw new ArgumentException("Cannot deserialise - requested type does not have a serialisation contract.");
            }
            var ms = new MemoryStream(objectBytes);
            var outputObj = default(T);
            if (lengthPrefix) {
                outputObj = (T) Serialiser.DeserializeWithLengthPrefix(ms, outputObj, typeof (T), PrefixStyle.Base128, 0);
            } else {
                outputObj = (T) Serialiser.Deserialize(ms, outputObj, typeof (T));
            }
            return outputObj;
        }

		private static void CheckPackageIOIsOK(Stream destination, Manifest manifest) {
			// Can we actually perform a write to the output?
			if (!destination.CanWrite) throw new IOException("Cannot write to destination/output stream!");
			if (manifest.PayloadItems.Any(item => !item.StreamHasBinding)) {
				throw new InvalidOperationException("Internal state of package writer inconsistent. " +
				                                    "Stream binding and manifest counts match, but binding identifiers do not in at least one instance.");
			}
		}

        

		




	}

    /// <summary>
	/// Represents the error that occurs when, during package I/O, 
	/// cryptographic key material associated with a payload item cannot be found. 
	/// </summary>
	public class ItemKeyMissingException : Exception
	{
		public ItemKeyMissingException (PayloadItem item) : base 
			(String.Format("A cryptographic key for item GUID {0} and relative path \"{1}\" could not be found.", 
			               item.Identifier.ToString(), item.RelativePath))
		{}
	}

	/// <summary>
	/// Represents the error that occurs when, during package I/O, 
	/// a configuration error causes an abort of the package I/O operation.
	/// </summary>
	public class PackageConfigurationException : Exception
	{
		public PackageConfigurationException (string message) : base(message)
		{
		}
	}


}