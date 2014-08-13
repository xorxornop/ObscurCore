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

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Defines data that must be available in manifest cryptography scheme configurations.
    /// </summary>
    public interface IManifestCryptographySchemeConfiguration
    {
        /// <summary>
        ///     Key confirmation configuration.
        ///     Used to validate the existence and validity of keying material
        ///     at the respondent's side without disclosing the key itself.
        /// </summary>
        AuthenticationFunctionConfiguration KeyConfirmation { get; }

        /// <summary>
        ///     Output of the <see cref="KeyConfirmation"/> scheme, given the correct key.
        /// </summary>
        byte[] KeyConfirmationVerifiedOutput { get; }

        /// <summary>
        ///     Configuration for the scheme used to derive cipher and authentication keys from an initial key.
        /// </summary>
        KeyDerivationConfiguration KeyDerivation { get; }

        /// <summary>
        ///     Configuration of the cipher used in encryption of the manifest.
        /// </summary>
        CipherConfiguration SymmetricCipher { get; }

        /// <summary>
        ///     Configuration of the function/scheme used in authentication of the manifest. 
        ///     Note: this must be of a MAC type.
        /// </summary>
        AuthenticationFunctionConfiguration Authentication { get; }

        /// <summary>
        ///     Output of the <see cref="Authentication"/> scheme, given the correct input and key.
        /// </summary>
        byte[] AuthenticationVerifiedOutput { get; }
    }
}
