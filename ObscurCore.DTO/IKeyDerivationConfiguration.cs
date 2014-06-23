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
    public interface IKeyDerivationConfiguration
    {
        /// <summary>
        ///     Key Derivation Function (KDF) being used to derive valid, secure working key material.
        /// </summary>
        string FunctionName { get; }

        /// <summary>
        ///     Configuration for the key derivation function.
        /// </summary>
        /// <remarks>Format of the configuration is that of the consuming type.</remarks>
        byte[] FunctionConfiguration { get; }

        /// <summary>
        ///     Data used by KDF to extend and/or strengthen base key material.
        /// </summary>
        byte[] Salt { get; }
    }
}
