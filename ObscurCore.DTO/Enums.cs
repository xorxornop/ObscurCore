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

using ProtoBuf;

namespace ObscurCore.DTO
{
	#region Cryptography
	[ProtoContract]
	public enum SymmetricCipherType
	{
		None,
		AEAD,
		Block,
		Stream
	}

	public enum KeyActions
	{
		Associate,
		Dissociate,
		/// <summary>
		/// Reserved for use. For a scheme where key state can be 
		/// verified with state at another session-state locality.
		/// </summary>
		Validate,
		/// <summary>
		/// Reserved for use. For a scheme where keys change state 
		/// deterministically at multiple session-state localities.
		/// </summary>
		Advance
	}

    /// <summary>
    /// Types of cryptography used for encrypting Manifests.
    /// </summary>
    public enum ManifestCryptographySchemes
    {
         /// <summary>
        /// Using a pre-agreed key. Simply uses a SymmetricCipherConfiguration object in serialised form for 
        /// configuration, and as such, allows rich customisation.
        /// </summary>
        UniversalSymmetric, 

		/// <summary>
		/// UM1-based hybrid (PKC-derived-key symmetric encryption) scheme.
		/// </summary>
		/// <remarks>
		/// Uses UM1 to generate a secret value, which is further derived with a KDF. 
		/// This derived secret is used as a symmetric cipher key, and optionally, to generate a MAC for the data.
		/// </remarks>
		UM1Hybrid,

        /// <summary>
        /// UM1-based hybrid (PKC-derived-key symmetric encryption) scheme that specifically uses Curve25519 EC scheme.
        /// </summary>
        /// <remarks>
		/// Uses Curve25519UM1 to generate a secret value, which is further derived with a KDF. 
		/// This derived secret is used as a symmetric cipher key, and optionally, to generate a MAC for the data.
		/// </remarks>
        Curve25519UM1Hybrid
    }
	#endregion

	#region Packaging
	/// <summary>
	/// Possible distinct types of payload item that should/can be treated differently by an application.
	/// </summary>
	public enum PayloadItemTypes
	{
		Binary = 0,
		UTF8,
        UTF32,
		KeyAction
	}
	#endregion
}
