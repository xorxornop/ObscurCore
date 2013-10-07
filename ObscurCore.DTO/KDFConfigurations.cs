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

namespace ObscurCore.DTO
{
    public class ScryptConfiguration
    {
        /// <summary>
        /// Power to raise the iteration count by, e.g. 2^n iterations. 
        /// Causes the algorithm to take more cumulative time.
        /// </summary>
        /// <remarks>
        /// General-use cost increase. Use to scale cost/difficulty without changing CPU or memory cost directly, only time.
        /// </remarks>
        public int IterationPower { get; set; }

        /// <summary>
        /// Blocks to operate on. Increases memory cost, as this algorithm is memory-hard. 
        /// </summary>
        /// <remarks>
        /// Use sparingly in constrained environment such as mobile. Scale according to memory advancements.
        /// </remarks>
        public int Blocks { get; set; }

        /// <summary>
        /// How many co-dependant mix operations must be performed.
        /// </summary>
        /// <remarks>
        /// Can be run in parallel, hence the name. Increases CPU cost. Scale according to CPU speed advancements.
        /// </remarks>
        public int Parallelism { get; set; }
    }

    public class PBKDF2Configuration
    {
        /// <summary>
        /// Blocks to operate on. Increases memory cost, as this algorithm is memory-hard. 
        /// </summary>
        /// <remarks>
        /// Currently, only HMACSHA256 is supported.
        /// </remarks>
        public int AlgorithmName { get; set; }

        /// <summary>
        /// Number of times the algorithm will be run sequentially. 
        /// Causes the algorithm to take more cumulative time.
        /// </summary>
        /// <remarks>
        /// General-use cost increase. Use to scale cost/difficulty without changing CPU or memory cost directly, only time.
        /// </remarks>
        public int Iterations { get; set; }
    }
}
