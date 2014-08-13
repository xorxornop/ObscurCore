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
    ///     Types of cryptographic scheme used in initial/primary
    ///     key derivation for a <see cref="Manifest" />.
    /// </summary>
    public enum ManifestCryptographyScheme
    {
        /// <summary>
        ///     No scheme is used.
        /// </summary>
        None,

        /// <summary>
        ///     A key known to both parties (sender and recipient) is used.
        /// </summary>
        SymmetricOnly,

        /// <summary>
        ///     Unified Model 1-pass EC-hybrid PKC scheme is used to derive a shared key.
        /// </summary>
        /// <remarks>
        ///     Uses UM1 public key scheme to generate a shared secret - sender and recipient
        ///     derive an identical value from their public and private keys, and an ephemeral,
        ///     one-time public key.
        /// </remarks>
        Um1Hybrid
    }
}
