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

using System.Collections.Generic;
using ObscurCore.DTO;

namespace ObscurCore
{
    /// <summary>
    /// API for manifest key providers to conform to.
    /// </summary>
    public interface IKeyProvider
    {
        /// <summary>
        /// Symmetric key(s) to decrypt a manifest with.
        /// </summary>
        IEnumerable<byte[]> SymmetricKeys { get; }

        /// <summary>
        /// EC key(s) to decrypt the manifest with.
        /// </summary>
        IEnumerable<EcKeyConfiguration> EcSenderKeys { get; }

        /// <summary>
        /// EC key(s) to decrypt the manifest with.
        /// </summary>
        IEnumerable<EcKeyConfiguration> EcReceiverKeys { get; }

        /// <summary>
        /// Curve25519 key(s) to decrypt a manifest with.
        /// </summary>
        IEnumerable<byte[]> Curve25519SenderKeys { get; }

        /// <summary>
        /// Curve25519 EC public key(s) to decrypt the manifest with.
        /// </summary>
        IEnumerable<byte[]> Curve25519ReceiverKeys { get; }
    }
}
