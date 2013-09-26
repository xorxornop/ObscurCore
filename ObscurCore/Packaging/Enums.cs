//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

namespace ObscurCore.Packaging
{
	/// <summary>
	/// Schemes for how the data constituting the payload items is physically arranged (sequence-wise) relative to each other.
	/// </summary>
	public enum PayloadLayoutSchemes
	{
		/// <summary>
		/// Streams written/read in randomly-shuffled order into/from one block, with no further modification.
		/// <para>Lowest security mode, but also the fastest.</para>
		/// </summary>
		Simple,
		/// <summary>
		/// Streams written/read in randomly-shuffled order, with fixed/variable lengths of random data padding the start and end of each.
		/// <para>Medium security mode. Only slightly slower than simple.</para>
		/// </summary>
		Frameshift,
#if(INCLUDE_FABRIC)
        /// <summary>
		/// Streams written/read in random "striped" pattern, in randomly-shuffled order.
		/// <para>Highest security mode, but also the slowest.</para>
		/// </summary>
		Fabric
#endif
	}
	
	public enum FrameshiftPaddingModes
	{
		FixedLength,
		VariableLength
	}

#if(INCLUDE_FABRIC)
    public enum FabricStripeModes
    {
        FixedLength,
        VariableLength
    }
#endif
}
