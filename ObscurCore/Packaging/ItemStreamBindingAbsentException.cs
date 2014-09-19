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

using System;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
    /// <summary>
    ///     Exception thrown when, during package I/O, a stream binding is missing from a payload item.
    /// </summary>
    public class ItemStreamBindingAbsentException : Exception
    {
        private const string NoStreamBindingMessage = "Item has no stream binding.";

        public ItemStreamBindingAbsentException() {}
        public ItemStreamBindingAbsentException(string message) : base(message) {}
        public ItemStreamBindingAbsentException(string message, Exception inner) : base(message, inner) {}

        public ItemStreamBindingAbsentException(IPayloadItem item) : base(NoStreamBindingMessage)
        {
            PayloadItem = item;
        }

        public ItemStreamBindingAbsentException(IPayloadItem item, Exception inner) : base(NoStreamBindingMessage, inner)
        {
            PayloadItem = item;
        }

        public IPayloadItem PayloadItem { get; private set; }
    }
}
