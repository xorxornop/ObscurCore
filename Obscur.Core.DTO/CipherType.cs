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

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Operation type of cipher, e.g. whether it operates
    ///     on discrete blocks, or as a stream.
    /// </summary>
    [ProtoContract]
    public enum CipherType
    {
        /// <summary>
        ///     Not a cipher.
        /// </summary>
        None = 0,

        /// <summary>
        ///     Cipher processes discrete blocks of input at a time.
        /// </summary>
        Block,

        /// <summary>
        ///     Cipher operates as a stream, e.g. it can process a single byte at a time.
        /// </summary>
        Stream
    }
}
