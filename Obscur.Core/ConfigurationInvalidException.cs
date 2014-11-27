#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using Obscur.Core.DTO;

namespace Obscur.Core
{
    /// <summary>
    ///     Represents an error that occurs because a configuration object in general is invalid, or a value thereof.
    ///     Used only for ObscurCore objects.
    /// </summary>
    public class ConfigurationInvalidException : Exception
    {
        private const string AttentionString =
            "Configuration is invalid.";

        public ConfigurationInvalidException() : base(AttentionString) {}
        public ConfigurationInvalidException(string message) : base(message) {}

        public ConfigurationInvalidException(string message, Exception inner)
            : base(message, inner) {}

        public ConfigurationInvalidException(Exception innerException)
            : base(AttentionString, innerException) {}
    }

    public enum InvalidConfigurationType
    {
        /// <summary>
        ///     Configuration for authentication is invalid.
        /// </summary>
        /// <seealso cref="AuthenticationConfiguration"/>
        Authentication,

        /// <summary>
        ///     Configuration for cipher is invalid.
        /// </summary>
        /// <seealso cref="CipherConfiguration"/>
        Cipher,

        /// <summary>
        ///     Configuration for key agreement is invalid.
        /// </summary>
        KeyAgreement,

        /// <summary>
        ///     Configuration for key confirmation is invalid.
        /// </summary>
        /// <seealso cref="AuthenticationConfiguration"/>
        KeyConfirmation,

        /// <summary>
        ///     Configuration for key derivation is invalid.
        /// </summary>
        /// <seealso cref="KeyDerivationConfiguration"/>
        KeyDerivationFunction,

        /// <summary>
        ///     Configuration for signature is invalid.
        /// </summary>
        Signature,

        /// <summary>
        ///     Configuration for payload multiplexer is invalid.
        /// </summary>
        PayloadMultiplexer,

        /// <summary>
        ///     Configuration for package manifest header is invalid.
        /// </summary>
        PackageManifestHeader,

        /// <summary>
        ///     Configuration for package manifest is invalid.
        /// </summary>
        PackageManifest
    }
}
