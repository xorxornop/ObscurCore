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

namespace ObscurCore
{
	public static class CryptographyExtensions
	{
		/// <summary>
		/// A constant time equals comparison - does not terminate early if
		/// test will fail.
		/// </summary>
		/// <param name="a">Array to compare against</param>
		/// <param name="b">Array to test for equality</param>
		/// <returns>If arrays equal <c>true</c>, false otherwise.</returns>
		public static bool SequenceEqualConstantTime (this byte[] a, byte[] b) {
			int i = a.Length;
			if (i != b.Length)
				return false;
			int cmp = 0;
			while (i != 0) {
				--i;
				cmp |= (a [i] ^ b [i]);
			}
			return cmp == 0;
		}
	}
}

