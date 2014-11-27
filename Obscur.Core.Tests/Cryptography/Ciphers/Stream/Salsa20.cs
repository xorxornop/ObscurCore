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

namespace ObscurCore.Tests.Cryptography.Ciphers.Stream
{
    internal class Salsa20 : StreamCipherTestBase
	{
		private static readonly string MSG = 
			  "00000000000000000000000000000000"
			+ "00000000000000000000000000000000"
			+ "00000000000000000000000000000000"
			+ "00000000000000000000000000000000"
		;

		public Salsa20 () : base(StreamCipher.Salsa20)
		{
			// Data from ESTREAM verified test vectors
			// http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/verified.test-vectors?rev=140&view=markup

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"[K128-IV64] Set 0, vector# 0",
				"80000000000000000000000000000000",
				"0000000000000000", 
				MSG,
				"4DFA5E481DA23EA09A31022050859936" + 
				"DA52FCEE218005164F267CB65F5CFD7F" + 
				"2B4F97E0FF16924A52DF269515110A07" + 
				"F9E460BC65EF95DA58F740B7D1DBB0AA"
			));
			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"[K128-IV64] Set 1, vector# 9", 
				"00400000000000000000000000000000", 
				"0000000000000000",
				MSG,
				"0471076057830FB99202291177FBFE5D" +
				"38C888944DF8917CAB82788B91B53D1C" +
				"FB06D07A304B18BB763F888A61BB6B75" +
				"5CD58BEC9C4CFB7569CB91862E79C459"
			));

			SegmentedVectorTests.Add (new SegmentedVectorTestCase (
				"[K128-IV64] Set 6, vector# 0",
				"0053A6F94C9FF24598EB3E91E4378ADD",
				"0D74DB42A91077DE",
				new TestVectorSegment[] {
					new TestVectorSegment (
						"stream[0..63]",
						0,
						"05E1E7BEB697D999656BF37C1B978806" +
						"735D0B903A6007BD329927EFBE1B0E2A" +
						"8137C1AE291493AA83A821755BEE0B06" +
						"CD14855A67E46703EBF8F3114B584CBA"
					),
					new TestVectorSegment (
						"stream[65472..65535]",
						65472,
						"1A70A37B1C9CA11CD3BF988D3EE4612D" +
						"15F1A08D683FCCC6558ECF2089388B8E" +
						"555E7619BF82EE71348F4F8D0D2AE464" +
						"339D66BFC3A003BF229C0FC0AB6AE1C6"
					),
					new TestVectorSegment (
						"stream[65536..65599]",
						65536,
						"4ED220425F7DDB0C843232FB03A7B1C7" +
						"616A50076FB056D3580DB13D2C295973" +
						"D289CC335C8BC75DD87F121E85BB9981" +
						"66C2EF415F3F7A297E9E1BEE767F84E2"
					),
					new TestVectorSegment (
						"stream[131008..131071]",
						131008,
						"E121F8377E5146BFAE5AEC9F422F474F" +
						"D3E9C685D32744A76D8B307A682FCA1B" +
						"6BF790B5B51073E114732D3786B985FD" +
						"4F45162488FEEB04C8F26E27E0F6B5CD"
					)
				}
			));

			SegmentedVectorTests.Add (new SegmentedVectorTestCase (
				"[K256-IV64] Set 6, vector# 0",
				"0053A6F94C9FF24598EB3E91E4378ADD" +
				"3083D6297CCF2275C81B6EC11467BA0D",
				"0D74DB42A91077DE",
				new TestVectorSegment[] {
					new TestVectorSegment (
						"stream[0..63]",
						0,
						"F5FAD53F79F9DF58C4AEA0D0ED9A9601" +
						"F278112CA7180D565B420A48019670EA" +
						"F24CE493A86263F677B46ACE1924773D" +
						"2BB25571E1AA8593758FC382B1280B71"
					),
					new TestVectorSegment (
						"stream[65472..65535]",
						65472,
						"B70C50139C63332EF6E77AC54338A407" +
						"9B82BEC9F9A403DFEA821B83F7860791" +
						"650EF1B2489D0590B1DE772EEDA4E3BC" +
						"D60FA7CE9CD623D9D2FD5758B8653E70"
					),
					new TestVectorSegment (
						"stream[65536..65599]",
						65536,
						"81582C65D7562B80AEC2F1A673A9D01C" +
						"9F892A23D4919F6AB47B9154E08E699B" +
						"4117D7C666477B60F8391481682F5D95" +
						"D96623DBC489D88DAA6956B9F0646B6E"
					),
					new TestVectorSegment (
						"stream[131008..131071]",
						131008,
						"A13FFA1208F8BF50900886FAAB40FD10" +
						"E8CAA306E63DF39536A1564FB760B242" +
						"A9D6A4628CDC878762834E27A541DA2A" +
						"5E3B3445989C76F611E0FEC6D91ACACC"
					)
				}
			));
		}
	}
}

