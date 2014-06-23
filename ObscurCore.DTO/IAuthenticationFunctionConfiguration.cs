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

namespace ObscurCore.DTO
{
    public interface IAuthenticationFunctionConfiguration
    {
        /// <summary>
        ///     Type of the function primitive, e.g. Digest, MAC, or KDF.
        /// </summary>
        string FunctionType { get; }

        /// <summary>
        ///     Name of the function used to verify some data (e.g. a key, a payload item, etc.).
        ///     This may be a key derivation function, MAC function, hash function, etc.
        /// </summary>
        string FunctionName { get; }

        /// <summary>
        ///     Configuration for the verification function, where applicable.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] FunctionConfiguration { get; }

        int? KeySizeBits { get; }

        byte[] Nonce { get; }

        /// <summary>
        ///     Salt for the verification function, where applicable.
        /// </summary>
        byte[] Salt { get; }

        /// <summary>
        ///     Additional data for the verification function, where applicable.
        /// </summary>
        byte[] AdditionalData { get; set; }
    }
}