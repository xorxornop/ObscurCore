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
    [ProtoContract]
    public class SignatureConfiguration : IDataTransferObject
    {
        [ProtoMember(1, IsRequired = true)]
        public SignatureScheme Scheme { get; set; }

        [ProtoMember(2, IsRequired = true)]
        public byte[] SchemeConfiguration { get; set; }

        /// <summary>
        ///     Hash function to convert potentially large input data (what is to be signed) into a short/small 
        ///     representation form that is more easily computed with. This smaller data form is what will actually be 
        ///     signed by the signature scheme.
        /// </summary>
        /// <remarks>
        ///     Hashing or other entropy-related functionality may also be specified/prescribed 
        ///     by the signature scheme <see cref="SchemeConfiguration"/>.
        /// </remarks>
        [ProtoMember(3, IsRequired = true)]
        public AuthenticationConfiguration Hashing { get; set; }
    }
}
