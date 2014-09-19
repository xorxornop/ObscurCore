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
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.DTO;
using ObscurCore.Support.Entropy;
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
        private const int InitialSeedSize = 128; // bytes (1024 bits)

        /// <summary>
        ///     Primary cryptographically-secure random number generator.
        /// </summary>
        /// <remarks>
        ///     Alternative RNGs/PRNGs can be seeded from this.
        /// </remarks>
        public static readonly CsRng EntropySupplier;

        private static readonly DtoSerialiser Serialiser = new DtoSerialiser();

        internal static readonly int PlatformWordSize = IntPtr.Size;
        internal static readonly int PlatformWordSizeBits = PlatformWordSize * 8;

        static StratCom()
        {
            var digest = AuthenticatorFactory.CreateHashPrimitive(EntropyHashFunction);

            var digestRng = new DigestCsRng(digest);
            digestRng.AddSeedMaterial(((UInt64) DateTime.UtcNow.Ticks).ToLittleEndian());

            var seed = new byte[InitialSeedSize];
            new ThreadedSeedRng().NextBytes(seed, 0, InitialSeedSize / 2);
            var rrwRng = new ReversedRandomWindowRng(digestRng,
                Athena.Cryptography.HashFunctions[EntropyHashFunction].OutputSize.BitsToBytes());
            rrwRng.NextBytes(seed, InitialSeedSize / 2, InitialSeedSize / 2);
            rrwRng.AddSeedMaterial(seed);
            rrwRng.NextBytes(seed);
            digestRng.AddSeedMaterial(seed);

            EntropySupplier = digestRng;
        }

        /// <summary>
        ///     Adds entropy from an external source to the central entropy supplier, 
        ///     <see cref="EntropySupplier"/>.
        ///     It is recommended to do so regularly from a high quality entropy source!
        /// </summary>
        public static void AddEntropy(byte[] entropy)
        {
            EntropySupplier.AddSeedMaterial(entropy);
        }

        /// <summary>
        ///     Adds entropy to the central entropy source, <see cref="EntropySupplier"/>, 
        ///     from a thread-based entropy collector.
        /// </summary>
        public static void AddEntropy(int? bytes = null)
        {
            var seed = new byte[bytes ?? InitialSeedSize];
            new ThreadedSeedRng().NextBytes(seed, 0, seed.Length);
            EntropySupplier.AddSeedMaterial(seed);
        }

        /// <summary>
        ///     Serialises a data transfer object (DTO) of type <typeparamref name="T"/> into 
        ///     an <paramref name="output"/> stream, optionally with a Base128 length prefix.
        /// </summary>
        /// <remarks>
        ///     Provides deserialisation capabilities for any object which derives from 
        ///     <see cref="IDataTransferObject"/> and that has a <see cref="ProtoContractAttribute"/> 
        ///     attribute (e.g. those from ObscurCore.DTO namespace).
        /// </remarks>
        /// <typeparam name="T">The type of object to serialise.</typeparam>
        /// <param name="obj">The <typeparamref name="T"/> to serialise.</param>
        /// <param name="output">The stream to write the serialised <typeparamref name="T"/> to.</param>
        /// <param name="prefixLength">
        ///     If <c>true</c>, the serialised object will be prefixed with its length in Base128 format. 
        ///     Use when recipient does not know data length, e.g. networked communications, or streams 
        ///     with multiple serialised objects.
        /// </param>
        public static void SerialiseDataTransferObject<T>(T obj, Stream output, bool prefixLength = false)
             where T : IDataTransferObject
        {
            Type type = typeof (T);
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
        ///     Deserialises a data transfer object (DTO) of type <typeparamref name="T"/> 
        ///     from an <paramref name="input"/> stream.
        /// </summary>
        /// <remarks>
        ///     Provides deserialisation capabilities for any object which derives from 
        ///     <see cref="IDataTransferObject"/> and that has a <see cref="ProtoContractAttribute"/> 
        ///     attribute (e.g. those from <see cref="ObscurCore.DTO"/> namespace).
        /// </remarks>
        /// <typeparam name="T">Data transfer object.</typeparam>
        /// <param name="input">The stream to read the serialised <typeparamref name="T"/> from.</param>
        /// <param name="lengthPrefixed">
        ///     If <c>true</c>, the serialised object is prefixed with its length in Base128 format. 
        ///     If <c>false</c>, the whole <paramref name="input"/> stream will be read.
        /// </param>
        public static T DeserialiseDataTransferObject<T>(Stream input, bool lengthPrefixed = false) 
            where T : IDataTransferObject
        {
            if (Serialiser.CanSerializeContractType(typeof (T)) == false) {
                throw new ArgumentException(
                    "Cannot deserialise - requested type does not have a serialisation contract.");
            }
            var outputObj = default(T);
            if (lengthPrefixed) {
                outputObj = (T)Serialiser.DeserializeWithLengthPrefix(input, outputObj, 
                    typeof(T), PrefixStyle.Base128, 0);
            } else {
                outputObj = (T)Serialiser.Deserialize(input, outputObj, typeof(T));
            }
            return outputObj;
        }
    }
}
