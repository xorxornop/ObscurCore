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

using ProtoBuf;

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Compression schemes for reducing the size of data.
    /// </summary>
    [ProtoContract]
    public enum CompressionScheme
    {
        /// <summary>
        ///     No compression to be applied.
        /// </summary>
        None,

        /// <summary>
        ///     Compression to be applied using LZ4 algorithm.
        /// </summary>
        LZ4
    }
}
