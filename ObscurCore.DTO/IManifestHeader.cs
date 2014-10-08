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
    ///     Interface for a header for a <see cref="Manifest"/>.
    /// </summary>
    public interface IManifestHeader
    {
        /// <summary>
        ///     Format version of the associated <see cref="Manifest"/> object.
        ///     Used to denote breaking changes that may cause incompatibility.
        /// </summary>
        int FormatVersion { get; }

        /// <summary>
        ///     The cryptographic scheme used to secure the manifest.
        /// </summary>
        ManifestCryptographyScheme CryptographyScheme { get; }

        /// <summary>
        ///     Configuration of the cryptographic scheme used to secure the Manifest.
        /// </summary>
        /// <remarks>
        ///     Format of the configuration is that of the consuming type.
        /// </remarks>
        byte[] CryptographySchemeConfiguration { get; }
    }
}
