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

using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Interface for a configuration of a function or scheme used for checking the authenticity 
    ///     (e.g. MAC functions) and/or integrity (e.g. hash functions) of data.
    /// </summary>
    public interface IAuthenticationFunctionConfiguration 
    {
        /// <summary>
        ///     Category/type of the function primitive, e.g. Digest, MAC, or KDF.
        /// </summary>
        [ProtoMember(1, IsRequired = true)]
        AuthenticationFunctionType FunctionType { get; set; }

        /// <summary>
        ///     Name of the function used to verify some data (e.g. a key, a payload item, etc.).
        ///     This may be a key derivation function, MAC function, hash function, etc.
        /// </summary>
        [ProtoMember(2, IsRequired = true)]
        string FunctionName { get; set; }

        /// <summary>
        ///     Configuration for the verification function, where applicable.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        [ProtoMember(3, IsRequired = false)]
        byte[] FunctionConfiguration { get; set; }

        /// <summary>
        ///     Size of the key in bits for the verification function, where applicable.
        /// </summary>
        [ProtoMember(4, IsRequired = false)]
        int? KeySizeBits { get; set; }

        /// <summary>
        ///     Salt for the verification function, where applicable.
        /// </summary>
        [ProtoMember(5, IsRequired = false)]
        byte[] Nonce { get; set; }

        /// <summary>
        ///     Salt for the verification function, where applicable.
        /// </summary>
        [ProtoMember(6, IsRequired = false)]
        byte[] Salt { get; set; }

        /// <summary>
        ///     Additional data for the verification function, where applicable.
        /// </summary>
        [ProtoMember(7, IsRequired = false)]
        byte[] AdditionalData { get; set; }
    }
}