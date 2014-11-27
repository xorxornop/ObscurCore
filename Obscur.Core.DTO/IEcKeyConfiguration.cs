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
    ///     Interface for configurations of an elliptic curve key.
    /// </summary>
    public interface IEcKeyConfiguration
    {
        /// <summary>
        ///     If <c>true</c>, key is public component of a keypair. Otherwise, key is private component.
        /// </summary>
        /// <seealso cref="EcKeypair"/>
        bool PublicComponent { get; }

        /// <summary>
        ///     Name of the curve provider. 
        ///     Used to look up relevant domain parameters to decode <see cref="EncodedKey"/>.
        /// </summary>
        string CurveProviderName { get; }

        /// <summary>
        ///     Name of the elliptic curve in the <see cref="CurveProviderName"/> provider's selection. 
        ///     Used to look up relevant domain parameters to decode <see cref="EncodedKey"/>.
        /// </summary>
        string CurveName { get; }

        /// <summary>
        ///     Byte-array-encoded form of the key.
        /// </summary>
        byte[] EncodedKey { get; }

        /// <summary>
        ///     Any additional data required for the <see cref="EncodedKey"/> 
        ///     (for example, special formatting, if any).
        /// </summary>
        byte[] AdditionalData { get; }
    }
}
