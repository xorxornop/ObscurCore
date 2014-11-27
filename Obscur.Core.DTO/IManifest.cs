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

using System.Collections.Generic;

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Interface for a <see cref="Manifest"/> for a package - payload configuration, contents, etc.
    /// </summary>
    public interface IManifest
    {
        /// <summary>
        ///     Sequence of payload item descriptors. Order must be preserved for data integrity.
        /// </summary>
        /// <remarks>
        ///     This may be a file system path or other schema.
        ///     <para>
        ///         WARNING: Ordering of this list of items MUST be maintained!
        ///         Failure to ensure this will result in total loss of package contents at unpackaging stage.
        ///     </para>
        /// </remarks>
        List<PayloadItem> PayloadItems { get; }

        /// <summary>
        ///     Configuration of the payload packaging.
        /// </summary>
        PayloadConfiguration PayloadConfiguration { get; }
    }
}
