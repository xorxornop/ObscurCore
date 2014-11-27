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
using System.Runtime.Serialization;

namespace Obscur.Core
{
	[Serializable]
	public class EnumerationParsingException : Exception
	{
		public EnumerationParsingException() {}
		public EnumerationParsingException(string message) : base(message) {}
		public EnumerationParsingException(string message, Exception inner) : base(message, inner) {}

		/// <summary>
		/// Initialises a new instance of the EnumerationParsingException class with diagnostic information.
		/// </summary>
		/// <param name="requested">Value of the enumeration type that parsing was attempted on.</param>
		/// <param name="eType">Enumeration type.</param>
		public EnumerationParsingException(string requested, Type eType) 
			: base("Enumeration member " + requested + " is unknown in " + eType.Name) {
		}

		protected EnumerationParsingException(
			SerializationInfo info,
			StreamingContext context) : base(info, context) {}
	}
}