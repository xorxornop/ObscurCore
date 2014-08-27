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

using System.IO;
using ObscurCore.DTO;
using ProtoBuf;

namespace ObscurCore
{
    /// <summary>
    /// Extension methods for data transfer object serialisation.
    /// </summary>
    public static class SerialisationExtensions
    {
        /// <summary>
        ///     Serialises a data transfer object (DTO) of type <typeparamref name="T"/> 
        ///     into a byte array (non-length-prefixed).
        /// </summary>
        /// <remarks>
        ///     Provides deserialisation capabilities for any object which derives from 
        ///     <see cref="IDataTransferObject"/> and that has a <see cref="ProtoContractAttribute"/> 
        ///     attribute (e.g. those from ObscurCore.DTO namespace).
        /// </remarks>
        /// <typeparam name="T">The type of object to serialise.</typeparam>
        /// <param name="obj">The object to serialise.</param>
        /// <returns>The serialised DTO in a byte array.</returns>
        public static byte[] SerialiseDto<T>(this T obj)
            where T : IDataTransferObject
        {
            var ms = new MemoryStream();
            StratCom.SerialiseDataTransferObject(obj, ms, false);
            return ms.ToArray();
        }

        /// <summary>
        ///     Serialises a data transfer object (DTO) of type <typeparamref name="T"/> 
        ///     into a <see cref="System.IO.Stream"/>, optionally with a Base128 length prefix.
        /// </summary>
        /// <remarks>
        ///     Provides deserialisation capabilities for any object which derives from 
        ///     <see cref="IDataTransferObject"/> and that has a <see cref="ProtoContractAttribute"/> 
        ///     attribute (e.g. those from ObscurCore.DTO namespace).
        /// </remarks>
        /// <typeparam name="T">The type of object to serialise.</typeparam>
        /// <param name="obj">The object to serialise.</param>
        /// <param name="prefixLength">
        ///     If <c>true</c>, the object will be prefixed with its length in Base128 format. 
        ///     Use when recipient does not know data length.
        /// </param>
        /// <returns>The serialised DTO in a <see cref="System.IO.MemoryStream"/>.</returns>
        public static MemoryStream SerialiseDto<T>(this T obj, bool prefixLength)
            where T : IDataTransferObject
        {
            var ms = new MemoryStream();
            StratCom.SerialiseDataTransferObject(obj, ms, prefixLength);
            return ms;
        }

        /// <summary>
        ///     Serialises a data transfer object (DTO) of type <typeparamref name="T"/> 
        ///     into a <see cref="System.IO.Stream"/>, optionally with a Base128 length prefix.
        /// </summary>
        /// <remarks>
        ///     Provides deserialisation capabilities for any object which derives from 
        ///     <see cref="IDataTransferObject"/> and that has a <see cref="ProtoContractAttribute"/> 
        ///     attribute (e.g. those from ObscurCore.DTO namespace).
        /// </remarks>
        /// <typeparam name="T">The type of object to serialise.</typeparam>
        /// <param name="obj">The object to serialise.</param>
        /// <param name="output">The stream to write the serialised object to.</param>
        /// <param name="prefixLength">
        ///     If <c>true</c>, the object will be prefixed with its length in Base128 format. 
        ///     Use when recipient does not know data length.
        /// </param>
        public static void SerialiseDto<T>(this T obj, Stream output, bool prefixLength = true)
            where T : IDataTransferObject
        {
            StratCom.SerialiseDataTransferObject(obj, output, prefixLength);
        }

        /// <summary>
        ///     Deserialises a data transfer object (DTO) of type <typeparamref name="T"/> from
        ///     a <see cref="System.IO.Stream"/>.
        /// </summary>
        /// <remarks>
        ///     Uses the serialiser in <see cref="StratCom"/>, <see cref="StratCom.Serialiser"/>.
        /// </remarks>
        /// <typeparam name="T">Data transfer object.</typeparam>
        /// <param name="input">The stream to read the serialised object from.</param>
        /// <param name="lengthPrefixed">
        ///     If <c>true</c>, the object is prefixed with its length in Base128 format. 
        ///     If <c>false</c>, the whole stream will be read.
        /// </param>
        public static T DeserialiseDto<T>(this Stream input, bool lengthPrefixed)
            where T : IDataTransferObject
        {
            return StratCom.DeserialiseDataTransferObject<T>(input, lengthPrefixed);
        }

        /// <summary>
        ///     Deserialises a data transfer object (DTO) of type <typeparamref name="T"/> from
        ///     a byte array.
        /// </summary>
        /// <remarks>
        ///     Provides deserialisation capabilities for any object which derives from 
        ///     <see cref="IDataTransferObject"/> and that has a <see cref="ProtoContractAttribute"/> 
        ///     attribute (e.g. those from ObscurCore.DTO namespace).
        /// </remarks>
        /// <typeparam name="T">Data transfer object.</typeparam>
        /// <param name="input">The stream to read the serialised object from.</param>
        public static T DeserialiseDto<T>(this byte[] input)
            where T : IDataTransferObject
        {
            return StratCom.DeserialiseDataTransferObject<T>(new MemoryStream(input), false);
        }
    }
}