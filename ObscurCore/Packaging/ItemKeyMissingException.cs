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
    ///     Represents the error that occurs when, during package I/O,
    ///     cryptographic key material associated with a payload item cannot be found.
    /// </summary>
    public class ItemKeyMissingException : Exception
    {
        public ItemKeyMissingException() {}
        public ItemKeyMissingException(string message) : base(message) {}
        public ItemKeyMissingException(string message, Exception inner) : base(message, inner) {}

        public ItemKeyMissingException(PayloadItem item) : base
            (String.Format("A cryptographic key for item GUID {0} and relative path \"{1}\" could not be found.",
                item.Identifier, item.Path)) {}
    }
}
