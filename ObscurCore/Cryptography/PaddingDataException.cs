﻿//
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

namespace ObscurCore.Cryptography
{
	/// <summary>
	/// Exception thrown when padding data is corrupted.
	/// </summary>
    [Serializable]
    public class PaddingDataException : CryptoException
    {
		private const string ExceptionMessage = "Padding bytes are invalid.";

        public PaddingDataException() : base(ExceptionMessage) {}
        public PaddingDataException(string message) : base(ExceptionMessage + "\n" + message) {}
        public PaddingDataException(string message, Exception inner) : base(message, inner) {}
    }
}