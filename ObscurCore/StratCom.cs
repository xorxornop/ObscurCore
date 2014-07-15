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
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.DTO;
using ObscurCore.Support.Random;
using ProtoBuf;

namespace ObscurCore
{
    /// <summary>
    ///     Strategic Command.
    ///     Holds various resources shared by the entirety of ObscurCore.
    /// </summary>
    public static class StratCom
    {
        private const HashFunction EntropyHashFunction = HashFunction.Blake2B512;
        private const int InitialSeedSize = 64; // bytes (512 bits)

        /// <summary>
        ///     Cryptographically-secure random number generator.
        /// </summary>
        public static readonly CsRng EntropySupplier;

        internal static readonly DtoSerialiser Serialiser = new DtoSerialiser();

        static StratCom()
        {
            var digestRng = new DigestCsRng(AuthenticatorFactory.CreateHashPrimitive(EntropyHashFunction));
            digestRng.AddSeedMaterial(((UInt64) DateTime.UtcNow.Ticks).ToLittleEndian());

            var seed = new byte[InitialSeedSize];
            new ThreadedSeedRng().NextBytes(seed, 0, InitialSeedSize / 2);
            var rrwRng = new ReversedRandomWindowRng(digestRng,
                Athena.Cryptography.HashFunctions[EntropyHashFunction].OutputSize / 8);
            rrwRng.NextBytes(seed, InitialSeedSize / 2, InitialSeedSize / 2);
            rrwRng.AddSeedMaterial(seed);
            rrwRng.NextBytes(seed);
            digestRng.AddSeedMaterial(seed);

            EntropySupplier = digestRng;
        }

        /// <summary>
        ///     Adds entropy from an external source to the central entropy supplier, EntropySupplier.
        ///     It is recommended to do so regularly from a high quality entropy source!
        /// </summary>
        public static void AddEntropy(byte[] entropy)
        {
            EntropySupplier.AddSeedMaterial(entropy);
        }

        /// <summary>
        ///     Adds entropy to the central entropy source, EntropySupplier, from a thread-based entropy collector.
        /// </summary>
        public static void AddEntropy()
        {
            var seed = new byte[InitialSeedSize];
            new ThreadedSeedRng().NextBytes(seed, 0, InitialSeedSize / 2);
            EntropySupplier.AddSeedMaterial(seed);
        }

        /// <summary>
        ///     Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO
        ///     namespace).
        /// </summary>
        /// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
        public static MemoryStream SerialiseDataTransferObject(object obj, bool prefixLength = false)
        {
            var ms = new MemoryStream();
            SerialiseDataTransferObject(obj, ms, prefixLength);
            return ms;
        }

        public static void SerialiseDataTransferObject(object obj, Stream output, bool prefixLength = false)
        {
            Type type = obj.GetType();
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
        ///     Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO
        ///     namespace).
        /// </summary>
        /// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
        public static T DeserialiseDataTransferObject<T>(byte[] objectBytes, bool prefixLength = false)
        {
            if (Serialiser.CanSerializeContractType(typeof (T)) == false) {
                throw new ArgumentException(
                    "Cannot deserialise - requested type does not have a serialisation contract.");
            }
            var ms = new MemoryStream(objectBytes);
            T outputObj = default(T);
            if (prefixLength) {
                outputObj =
                    (T) Serialiser.DeserializeWithLengthPrefix(ms, outputObj, typeof (T), PrefixStyle.Base128, 0);
            } else {
                outputObj = (T) Serialiser.Deserialize(ms, outputObj, typeof (T));
            }
            return outputObj;
        }

        /// <summary>
        ///     Reads a serialiser-length-prefixed DTO object from a stream.
        /// </summary>
        /// <typeparam name="T">Type of the DTO object.</typeparam>
        /// <param name="input">Stream to read the serialised object from.</param>
        /// <returns>Deserialised DTO object</returns>
        public static T DeserialiseDataTransferObject<T>(Stream input)
        {
            if (Serialiser.CanSerializeContractType(typeof (T)) == false) {
                throw new ArgumentException(
                    "Cannot deserialise - requested type does not have a serialisation contract.");
            }
            var outputObj =
                (T) Serialiser.DeserializeWithLengthPrefix(input, default(T), typeof (T), PrefixStyle.Base128, 0);
            return outputObj;
        }
    }
}
