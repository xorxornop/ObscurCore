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

namespace ObscurCore
{
    /// <summary>
    /// Requirements for padding in a block cipher mode of operation.
    /// </summary>
    public enum PaddingRequirement
    {
        None = 0,
        /// <summary>
        /// Padding scheme must be used if plaintext length is less than 1 block length.
        /// </summary>
        IfUnderOneBlock,
        /// <summary>
        /// Self-explanatory.
        /// </summary>
        Always
    }
}