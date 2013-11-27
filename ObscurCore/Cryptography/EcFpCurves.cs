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

namespace ObscurCore.Cryptography
{
    // No MD4/MD5 support is being included because they are so badly compromised.
	// Inability of use may hopefully deter one from thinking that they are suitable for use - which, for almost all cases, they are not.
	
	/// <summary>
	/// Elliptic-Curve curves over GF(p) .
	/// </summary>
	public enum EcFpCurves
	{
		None,
		BrainpoolP160r1,
		BrainpoolP192r1,
		BrainpoolP224r1,
		BrainpoolP256r1,
		BrainpoolP320r1,
		BrainpoolP384r1,
		BrainpoolP512r1
	}
}
