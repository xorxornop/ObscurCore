//
//  Copyright 2014  Matthew Ducker
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

namespace ObscurCore.Tests.Cryptography.Ciphers.Stream
{
	#if INCLUDE_RC4
	public class Rc4 : StreamCipherTestBase
	{
		private static readonly string KEY = 
			"0123456789ABCDEF";

		public Rc4 () : base(ObscurCore.Cryptography.Ciphers.Stream.StreamCipher.Rc4)
		{
			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"n/a",
				KEY,
				"",
				"4e6f772069732074",
				"3afbb5c77938280d"
			));
			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"n/a",
				KEY,
				"",
				"68652074696d6520",
				"1cf1e29379266d59"
			));
			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"n/a",
				KEY,
				"",
				"666f7220616c6c20",
				"12fbb0c771276459"
			));
		}
	}
	#endif
}

