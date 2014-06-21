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

namespace ObscurCore.DTO
{
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
        ///     Item handling behaviour category.
        ///     Key actions should be handled differently from the others.
        /// </summary>
        PayloadItemType Type { get; }

        /// <summary>
        ///     Path of the stored data. 'Path' syntax may correspond to a key-value collection, filesystem, or other hierarchal
        ///     schema.
        ///     Syntax uses '/' to seperate stores/directories. Item names may or may not have extensions (if
        ///     files/binary-data-type).
        /// </summary>
        string RelativePath { get; }

        /// <summary>
        ///     Length of the item inside of the payload, excluding any additional length imparted by the payload layout scheme.
        /// </summary>
        long InternalLength { get; }

        /// <summary>
        ///     Length of the item outside of the payload, unmodified, as it was before inclusion.
        /// </summary>
        long ExternalLength { get; }

        /// <summary>
        ///     Symmetric cipher configuration for this payload item.
        /// </summary>
        CipherConfiguration SymmetricCipher { get; }

        /// <summary>
        ///     Ephemeral cryptographic key for encryption of the payload item.
        ///     Required if <see cref="IPayloadItem.KeyDerivation" /> is not present.
        /// </summary>
        byte[] SymmetricCipherKey { get; }

        /// <summary>
        ///     Authentication configuration for the payload item.
        ///     Must be of a MAC type.
        /// </summary>
        AuthenticationFunctionConfiguration Authentication { get; }

        /// <summary>
        ///     Ephemeral cryptographic key for authentication of the payload item.
        ///     Required if <see cref="IPayloadItem.KeyDerivation" /> is not present.
        /// </summary>
        byte[] AuthenticationKey { get; }

        /// <summary>
        ///     Output of the authentication scheme given correct input data.
        /// </summary>
        byte[] AuthenticationVerifiedOutput { get; }

        /// <summary>
        ///     Key confirmation configuration for this payload item.
        ///     Used to validate the existence and validity of keying material
        ///     at the respondent's side without disclosing the key itself.
        /// </summary>
        AuthenticationFunctionConfiguration KeyConfirmation { get; set; }

        byte[] KeyConfirmationVerifiedOutput { get; set; }

        /// <summary>
        ///     Key derivation configuration for this payload item.
        ///     Used to derive cipher and authentication keys from a single pre-established key.
        /// </summary>
        KeyDerivationConfiguration KeyDerivation { get; set; }
    }
}