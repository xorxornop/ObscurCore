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

using System;
using System.IO;

namespace ObscurCore.DTO
{
    /// <summary>
    ///     Stripped-down access interface for payload items and compatible objects.
    /// </summary>
    public interface IStreamBinding
    {
        Guid Identifier { get; }
        Stream StreamBinding { get; }
        bool StreamInitialised { get; }
        bool StreamHasBinding { get; }
        long InternalLength { get; set; }
        long ExternalLength { get; set; }
    }
}