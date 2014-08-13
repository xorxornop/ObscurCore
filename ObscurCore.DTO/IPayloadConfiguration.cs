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
    ///     Interface for configuration for a scheme controlling how payload items 
    ///     are physically laid out (as sequences of bytes) relative to each other.
    /// </summary>
    public interface IPayloadConfiguration
    {
        /// <summary>
        ///     Name of the payload layout scheme, e.g. Frameshift.
        /// </summary>
        string SchemeName { get; }

        /// <summary>
        ///     Configuration for the layout-scheme-specific payload I/O module.
        /// </summary>
        /// <remarks>
        ///     Format of the configuration is that of the consuming type.
        /// </remarks>
        byte[] SchemeConfiguration { get; }

        /// <summary>
        ///     Name of the PRNG used to select which item to read/write from/to the payload.
        /// </summary>
        string PrngName { get; }

        /// <summary>
        ///     Configuration for the stream-selection PRNG.
        /// </summary>
        /// <remarks>
        ///     Format of the configuration is that of the consuming type.
        /// </remarks>
        byte[] PrngConfiguration { get; }
    }
}