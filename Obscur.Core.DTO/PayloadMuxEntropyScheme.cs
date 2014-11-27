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
    ///     Schemes for providing entropy as necessary for the payload 
    ///     multiplexing/demultiplexing process.
    /// </summary>
    [ProtoContract]
    public enum PayloadMuxEntropyScheme
    {
        /// <summary>
        ///     Stream cipher (functioning as a CSPRNG) generates entropy on-demand.
        /// </summary>
        StreamCipherCsprng,

        /// <summary>
        ///     All necessary entropy for operations is preallocated (generated in advance).
        /// </summary>
        Preallocation
    }
}
