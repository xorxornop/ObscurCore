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

using Obscur.Core.Cryptography.Ciphers.Stream;

namespace Obscur.Core.Tests.Cryptography.Ciphers.Stream
{
    internal class Hc128 : StreamCipherTestBase
	{
		private static readonly string MSG = "00000000000000000000000000000000" + 
		                                     "00000000000000000000000000000000" + 
		                                     "00000000000000000000000000000000" + 
		                                     "00000000000000000000000000000000";

		public Hc128 () : base(StreamCipher.Hc128)
		{
			// Data from ESTREAM verified test vectors
			// http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/hc-256/hc-128/verified.test-vectors?rev=210&view=markup

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"[K128-IV128] Set 2, vector# 0",
				"00000000000000000000000000000000",
				"00000000000000000000000000000000",
				MSG,
				"82001573A003FD3B7FD72FFB0EAF63AA" +
				"C62F12DEB629DCA72785A66268EC758B" +
				"1EDB36900560898178E0AD009ABF1F49" +
				"1330DC1C246E3D6CB264F6900271D59C"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"[K128-IV128] Set 6, vector# 1",
				"0558ABFE51A4F74A9DF04396E93C8FE2",
				"167DE44BB21980E74EB51C83EA51B81F",
				MSG,
				"4F864BF3C96D0363B1903F0739189138" +
				"F6ED2BC0AF583FEEA0CEA66BA7E06E63" +
				"FB28BF8B3CA0031D24ABB511C57DD17B" +
				"FC2861C32400072CB680DF2E58A5CECC"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"[K128-IV128] Set 6, vector# 2",
				"0A5DB00356A9FC4FA2F5489BEE4194E7",
				"1F86ED54BB2289F057BE258CF35AC128",
				MSG,
				"82168AB0023B79AAF1E6B4D823855E14" +
				"A7084378036A951B1CFEF35173875ED8" +
				"6CB66AB8410491A08582BE40080C3102" +
				"193BA567F9E95D096C3CC60927DD7901"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"[K128-IV128] Set 6, vector# 3",
				"0F62B5085BAE0154A7FA4DA0F34699EC",
				"288FF65DC42B92F960C72E95FC63CA31",
				MSG,
				"1CD8AEDDFE52E217E835D0B7E84E2922" +
				"D04B1ADBCA53C4522B1AA604C42856A9" +
				"0AF83E2614BCE65C0AECABDD8975B557" +
				"00D6A26D52FFF0888DA38F1DE20B77B7"
			));

			SegmentedVectorTests.Add (new SegmentedVectorTestCase (
				"[K128-IV128] Set 6, vector# 0",
				"0F62B5085BAE0154A7FA4DA0F34699EC",
				"288FF65DC42B92F960C72E95FC63CA31",
				new TestVectorSegment[] {
					new TestVectorSegment (
						"stream[0..63]",
						0,
						"1CD8AEDDFE52E217E835D0B7E84E2922" +
						"D04B1ADBCA53C4522B1AA604C42856A9" +
						"0AF83E2614BCE65C0AECABDD8975B557" +
						"00D6A26D52FFF0888DA38F1DE20B77B7"
					),
					new TestVectorSegment (
						"stream[65472..65535]",
						65472,
						"BB599F93F4F244D717CA9818212B06D5" +
						"6D99AD4CA1F78725DBA89EA1D1F05B27" +
						"093A17D745396D8CFD0256CD50674046" +
						"13108E2200A8F1C49075B376A7460515"
					),
					new TestVectorSegment (
						"stream[65536..65599]",
						65536,
						"996C074A7C7C524F539037A8A9F3D193" +
						"3BC311B548BD567F8AE1B4325C51C5F3" +
						"4B0DE1B4A4651829108CA92AE23D57C7" +
						"0EAFA766097DB0539BE77E6500703746"
					),
					new TestVectorSegment (
						"stream[131008..131071]",
						131008,
						"43EF1ADFE8265C46FF7FBA43B78F899F" +
						"22C3B9F069B786982145D601627CDC49" +
						"2D27BB8D70FF6DA908F2606A0C44690C" +
						"8502F9CFB3BD6CBFC9205470E3ABA387"
					)
				}
			));

		}
	}
}

