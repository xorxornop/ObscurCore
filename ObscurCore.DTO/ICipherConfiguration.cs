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
    public interface ICipherConfiguration
    {
        /// <summary>
        ///     Category/type of the cipher primitive, e.g. block, AEAD, or stream.
        ///     AEAD must be specified if using a block cipher in a AEAD mode of operation.
        /// </summary>
        CipherType Type { get; }

        /// <summary>
        ///     Name of the cipher primitive, e.g. AES.
        /// </summary>
        string CipherName { get; }

        /// <summary>
        ///     Size of the key being used, in bits.
        /// </summary>
        int KeySizeBits { get; }

        /// <summary>
        ///     Data that initialises the  state of the cipher prior to processing any data.
        /// </summary>
        byte[] InitialisationVector { get; }

        /// <summary>
        ///     Mode of operation used in the cipher, where applicable (block and AEAD ciphers).
        /// </summary>
        string ModeName { get; }

        /// <summary>
        ///     Size of each block of data in bits.
        /// </summary>
        int? BlockSizeBits { get; }

        /// <summary>
        ///     Scheme utillised to 'pad' blocks to full size where required.
        /// </summary>
        string PaddingName { get; }
    }
}
