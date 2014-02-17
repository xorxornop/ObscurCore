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
using System.Text;
using System.Threading;
using ObscurCore.Cryptography.Entropy;
using ProtoBuf;

namespace ObscurCore
{
	/// <summary>
	/// Strategic Command. 
	/// Holds various resources shared by the entirety of ObscurCore.
	/// </summary>
    public static class StratCom
    {
        private const int InitialSeedSize = 64; // bytes
		public static readonly SecureRandom EntropySupplier = SecureRandom.GetInstance("SHA256PRNG");

        internal static readonly DTOSerialiser Serialiser = new DTOSerialiser();

        static StratCom() {
            EntropySupplier.SetSeed(SecureRandom.GetSeed(InitialSeedSize));
            EntropySupplier.SetSeed(Thread.CurrentThread.ManagedThreadId);
        }

		/// <summary>
		/// Adds entropy to the entropy source. 
		/// Important to do so periodically from a high quality entropy source!
		/// </summary>
		public static void AddEntropy (byte[] entropy) {
			EntropySupplier.SetSeed (entropy);
		}

        /// <summary>
        /// Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO namespace).
        /// </summary>
        /// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
        public static MemoryStream SerialiseDataTransferObject(object obj, bool prefixLength = false) {
            var ms = new MemoryStream();
            SerialiseDataTransferObject(obj, ms, prefixLength);
            return ms;
        }

        public static void SerialiseDataTransferObject(object obj, Stream output, bool prefixLength = false) {
            var type = obj.GetType();
			if (Serialiser.CanSerializeContractType(type) == false) {
                throw new ArgumentException(
                    "Cannot serialise - object type does not have a serialisation contract.", "obj");
            }
            if (prefixLength) {
                Serialiser.SerializeWithLengthPrefix(output, obj, type, PrefixStyle.Base128, 0);
            } else {
                Serialiser.Serialize(output, obj);
            }
        }

        /// <summary>
        /// Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO namespace).
        /// </summary>
        /// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
        public static T DeserialiseDataTransferObject<T>(byte[] objectBytes, bool prefixLength = false) {
			if (Serialiser.CanSerializeContractType(typeof (T)) == false) {
                throw new ArgumentException(
                    "Cannot deserialise - requested type does not have a serialisation contract.");
            }
            var ms = new MemoryStream(objectBytes);
            var outputObj = default(T);
            if (prefixLength) {
                outputObj = (T) Serialiser.DeserializeWithLengthPrefix(ms, outputObj, typeof (T), PrefixStyle.Base128, 0);
            } else {
                outputObj = (T) Serialiser.Deserialize(ms, outputObj, typeof (T));
            }
            return outputObj;
        }

        /// <summary>
        /// Reads a serialiser-length-prefixed DTO object from a stream.
        /// </summary>
        /// <typeparam name="T">Type of the DTO object.</typeparam>
        /// <param name="input">Stream to read the serialised object from.</param>
        /// <returns>Deserialised DTO object</returns>
        public static T DeserialiseDataTransferObject<T>(Stream input) {
			if (Serialiser.CanSerializeContractType(typeof (T)) == false) {
                throw new ArgumentException(
                    "Cannot deserialise - requested type does not have a serialisation contract.");
            }
            var outputObj = (T) Serialiser.DeserializeWithLengthPrefix(input, default(T), typeof (T), PrefixStyle.Base128, 0);
            return outputObj;
        }
    }
}
