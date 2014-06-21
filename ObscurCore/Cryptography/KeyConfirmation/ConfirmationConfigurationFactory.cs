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

using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyConfirmation
{
    public static class ConfirmationConfigurationFactory
    {
        /// <summary>
        /// Creates a configuration for key confirmation using a MAC construction. 
        /// </summary>
        /// <param name="macFunctionEnum">Hash function to use as basis of HMAC construction.</param>
        /// <returns>A key confirmation as a <see cref="AuthenticationFunctionConfiguration"/>.</returns>
        public static AuthenticationFunctionConfiguration GenerateConfiguration(MacFunction macFunctionEnum)
        {
            int outputSize;
            var config = AuthenticationConfigurationFactory.CreateAuthenticationConfiguration(macFunctionEnum, out outputSize);

            return config;
        }

        /// <summary>
        /// Creates a configuration for key confirmation using an HMAC construction. 
        /// </summary>
        /// <param name="hashFunctionEnum">Hash function to use as basis of HMAC construction.</param>
        /// <returns>A key confirmation as a <see cref="AuthenticationFunctionConfiguration"/>.</returns>
        public static AuthenticationFunctionConfiguration GenerateConfiguration(HashFunction hashFunctionEnum)
        {
            int outputSize;
            var config = AuthenticationConfigurationFactory.CreateAuthenticationConfigurationHmac(hashFunctionEnum, out outputSize);

            return config;
        }

        /// <summary>
        /// Creates a configuration for key confirmation using an CMAC/OMAC1 construction. 
        /// </summary>
        /// <param name="cipherEnum">Block cipher to use as basis of CMAC construction.</param>
        /// <returns>A key confirmation as a <see cref="AuthenticationFunctionConfiguration"/>.</returns>
        public static AuthenticationFunctionConfiguration GenerateConfiguration(BlockCipher cipherEnum)
        {
            int outputSize;
            var config = AuthenticationConfigurationFactory.CreateAuthenticationConfigurationCmac(cipherEnum, out outputSize);

            return config;
        }
    }
}
