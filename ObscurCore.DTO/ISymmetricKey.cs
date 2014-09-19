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
    ///     An interface for a symmetric key.
    /// </summary>
    public interface ISymmetricKey : ISymmetricKeyPermissions, IPossessConfirmationCanary
    {
        /// <summary>
        ///     Key for use in encryption or authentication schemes etc. after further derivation.
        /// </summary>
        byte[] Key { get; set; }

        /// <summary>
        ///     Any additional data required for the <see cref="Key"/> 
        ///     (for example, special formatting, if any).
        /// </summary>
        byte[] AdditionalData { get; set; }
    }
}
