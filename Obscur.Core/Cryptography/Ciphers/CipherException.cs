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

namespace Obscur.Core.Cryptography.Ciphers
{
    public class CipherException : CryptographicException
    {
        private const string ExceptionMessage =
            "Unspecified cryptographic cipher error.";

        public CipherException() {}
        public CipherException(string message) : base(message ?? ExceptionMessage) {}
        public CipherException(string message, Exception inner) : base(message ?? ExceptionMessage, inner) {}
    }
}
