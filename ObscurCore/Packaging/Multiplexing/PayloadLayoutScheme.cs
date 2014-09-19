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

namespace ObscurCore.Packaging.Multiplexing
{
    /// <summary>
    ///     Schemes for how data constituting payload items is spatially arranged (sequence-wise) relative to each other.
    /// </summary>
    public enum PayloadLayoutScheme
    {
        /// <summary>
        ///     Items written/read in randomly-shuffled order with no further modification.
        /// </summary>
        /// <remarks>Lowest security mode, but the fastest.</remarks>
        Simple,

        /// <summary>
        ///     Items written/read in randomly-shuffled order, with fixed/variable lengths of random data padding the start and end
        ///     of each.
        /// </summary>
        /// <remarks>Medium security mode. Only very slightly slower than <see cref="Simple" />. Incurs some storage inefficiency.</remarks>
        Frameshift,

#if INCLUDE_FABRIC
        /// <summary>
        ///     Items written/read in in randomly-shuffled order in pattern of "stripes" of fixed/variable length.
        /// </summary>
        /// <remarks>Highest security mode, but also the slowest.</remarks>
        Fabric
#endif
    }
}
