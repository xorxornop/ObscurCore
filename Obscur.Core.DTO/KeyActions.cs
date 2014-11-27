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

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Action to perform with a key upon its receipt.
    /// </summary>
    public enum KeyActions
    {
        /// <summary>
        ///     Do nothing with the key.
        /// </summary>
        None,

        /// <summary>
        ///     Associate the key with the sender/origin.
        /// </summary>
        Associate,

        /// <summary>
        ///     Dissociate the key with the sender/origin.
        /// </summary>
        Dissociate,

        /// <summary>
        ///     Reserved for use. For a scheme where key state can be
        ///     verified with state at another session-state locality.
        /// </summary>
        Validate,

        /// <summary>
        ///     Reserved for use. For a scheme where keys change state
        ///     deterministically at multiple session-state localities.
        /// </summary>
        Advance
    }
}
