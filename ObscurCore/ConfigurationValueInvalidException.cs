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

namespace ObscurCore
{
	[Serializable]
	public class ConfigurationValueInvalidException : ConfigurationInvalidException
	{
		private const string AttentionString =
			"Value is invalid for object state (relative) or for object specification (absolute).";

		public ConfigurationValueInvalidException() : base(AttentionString) {}
		public ConfigurationValueInvalidException(string message) : base(message) {}

		public ConfigurationValueInvalidException (string message, Exception inner) 
			: base(message, inner) { }

		public ConfigurationValueInvalidException (Exception innerException) 
			: base(AttentionString, innerException) { }

		protected ConfigurationValueInvalidException(
			SerializationInfo info,
			StreamingContext context) : base(info, context) {}
	}
}