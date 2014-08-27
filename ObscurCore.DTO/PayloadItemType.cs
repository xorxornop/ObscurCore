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
    ///     Possible distinct types of payload item that can/should be
    ///     handled differently by an application/program.
    /// </summary>
    public enum PayloadItemType : byte
    {
        /// <summary>
        ///     Binary data conforming with the ObscurCore filesystem schema.
        /// </summary>
        File,

        /// <summary>
        ///     Text data capable of conforming with the ObscurCore filesystem schema
        ///     (treated as a text-type <see cref="File" />).
        /// </summary>
        Message,

        /// <summary>
        ///     Value within some key-value system, that should not be treated as either a
        ///     <see cref="File" /> or <see cref="Message" />.
        /// </summary>
        Value,

        /// <summary>
        ///     Action to perform with an enclosed/encapsulated key.
        /// </summary>
        KeyAction
    }
}
