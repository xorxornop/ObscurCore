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
    ///     An interface for an elliptic curve key.
    /// </summary>
    /// <seealso cref="IEcKeypair"/>
    public interface IEcKey 
    {
        /// <summary>
        ///     If <c>true</c>, key is public component of a keypair. Otherwise, key is private component.
        /// </summary>
        bool PublicComponent { get; set; }

        /// <summary>
        ///     Name of the curve provider. 
        ///     Used to look up relevant domain parameters to decode <see cref="EncodedKey"/>.
        /// </summary>
        string CurveProviderName { get; set; }

        /// <summary>
        ///     Name of the elliptic curve in the <see cref="CurveProviderName"/> provider's selection. 
        ///     Used to look up relevant domain parameters to decode <see cref="EncodedKey"/>.
        /// </summary>
        string CurveName { get; set; }

        /// <summary>
        ///     Encoded form of the key.
        /// </summary>
        byte[] EncodedKey { get; set; }

        /// <summary>
        ///     Any additional data required for the <see cref="EncodedKey"/> 
        ///     (for example, special formatting, if any).
        /// </summary>
        byte[] AdditionalData { get; set; }
    }
}
