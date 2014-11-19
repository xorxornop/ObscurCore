#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Configuration for a digital signature instance using the Ed25519 signature scheme.
    /// </summary>
    [ProtoContract]
    public class Ed25519Configuration : IDataTransferObject
    {
        public Ed25519Configuration()
        {
            HashFunctionName = "Sha512";
        }

        /// <summary>
        ///     Used by the Ed25519 primitive internally for deterministic key generation, signing, etc.
        ///     Default hash function should be SHA-512, as defined by the formal Ed25519 specification -
        ///     and in a de-facto manner through its use in the popular NaCl software package, etc.
        /// </summary>
        public string HashFunctionName { get; set; }

        public AuthenticationConfiguration Hashing { get; set; }

        public byte[] REncoded { get; set; }

        public byte[] SEncoded { get; set; }
    }
}
