#region License

// 	Copyright 2014-2014 Matthew Ducker
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
    ///     An interface for an elliptic curve keypair.
    /// </summary>
    public interface IECKeypair : IAsymmetricKeyPermissions, IPossessConfirmationCanary
    {
        /// <summary>
        ///     Name of the curve provider. 
        ///     Used to look up relevant domain parameters to decode 
        ///     <see cref="EncodedPublicKey"/> and <see cref="EncodedPrivateKey"/>.
        /// </summary>
        string CurveProviderName { get; }

        /// <summary>
        ///     Name of the elliptic curve in the <see cref="CurveProviderName"/> provider's selection. 
        ///     Used to look up relevant domain parameters to decode 
        ///     <see cref="EncodedPublicKey"/> and <see cref="EncodedPrivateKey"/>.
        /// </summary>
        string CurveName { get; }

        /// <summary>
        ///     Encoded form of the public key.
        /// </summary>
        byte[] EncodedPublicKey { get; }

        /// <summary>
        ///     Encoded form of the private key.
        /// </summary>
        byte[] EncodedPrivateKey { get; }

        /// <summary>
        ///     Any additional data required for the <see cref="EncodedPublicKey"/> 
        ///     and <see cref="EncodedPrivateKey"/> (for example, special formatting, if any).
        /// </summary>
        byte[] AdditionalData { get; }
    }
}
