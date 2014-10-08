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

using System;
using System.IO;

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Interface for an item in the payload of a package.
    /// </summary>
    public interface IPayloadItem : IDisposable
    {
        /// <summary>
        ///     Identifier used for stream binding.
        /// </summary>
        Guid Identifier { get; }

        /// <summary>
        ///     Stream that the payload item is bound to.
        ///     For example, if the item is being read from a payload, the binding will be the location read to.
        /// </summary>
        Stream StreamBinding { get; }

        /// <summary>
        ///     Item type. Used for indicating how an item should be handled.
        /// </summary>
        PayloadItemType Type { get; }

        /// <summary>
        ///     Path and/or name of the stored data.
        /// </summary>
        /// <remarks>
        ///     Path syntax may correspond to a filesystem, key-value collection, or the like.
        /// </remarks>
        string Path { get; }

        /// <summary>
        ///     Length of the item outside of the payload, unmodified, as it was before inclusion.
        /// </summary>
        long ExternalLength { get; }

        /// <summary>
        ///     Length of the item inside of the payload, excluding any additional length imparted by the payload layout scheme.
        /// </summary>
        long InternalLength { get; }

        /// <summary>
        ///     Name of the format that the content is stored as.
        /// </summary>
        string FormatName { get; }

        /// <summary>
        ///     Data for the format of the content, where applicable 
        ///     (not sufficiently described by <see cref="FormatName"/>).
        /// </summary>
        byte[] FormatData { get; }

        /// <summary>
        ///     Symmetric cipher configuration for this payload item.
        /// </summary>
        CipherConfiguration SymmetricCipher { get; }

        /// <summary>
        ///     Ephemeral key for encryption of the payload item.
        ///     Required if <see cref="KeyDerivation" /> is not present.
        /// </summary>
        byte[] SymmetricCipherKey { get; }

        /// <summary>
        ///     Authentication configuration for the payload item.
        ///     Note: this must be of a MAC type.
        /// </summary>
        AuthenticationConfiguration Authentication { get; }

        /// <summary>
        ///     Ephemeral key for authentication of the payload item.
        ///     Required if <see cref="KeyDerivation"/> is not present.
        /// </summary>
        byte[] AuthenticationKey { get; }

        /// <summary>
        ///     Output of the <see cref="Authentication"/> scheme, given the correct input and key.
        /// </summary>
        byte[] AuthenticationVerifiedOutput { get; }

        /// <summary>
        ///     Key confirmation configuration for this payload item.
        ///     Used to validate the existence and validity of keying material
        ///     at the respondent's side without disclosing the key itself.
        ///     Required if <see cref="SymmetricCipherKey" /> and <see cref="AuthenticationKey" /> are not
        ///     present.
        /// </summary>
        AuthenticationConfiguration KeyConfirmation { get; set; }

        /// <summary>
        ///     Output of the <see cref="KeyConfirmation"/> scheme, given the correct key.
        /// </summary>
        byte[] KeyConfirmationVerifiedOutput { get; set; }

        /// <summary>
        ///     Key derivation configuration for this payload item.
        ///     Used to derive cipher and authentication keys from a single key.
        ///     Required if <see cref="SymmetricCipherKey" /> and <see cref="AuthenticationKey" /> are not
        ///     present.
        /// </summary>
        KeyDerivationConfiguration KeyDerivation { get; set; }
    }
}