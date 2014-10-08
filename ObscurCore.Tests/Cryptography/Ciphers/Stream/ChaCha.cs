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

namespace ObscurCore.Tests.Cryptography.Ciphers.Stream
{
    internal class ChaCha : StreamCipherTestBase
	{
//		private static readonly string MSG = 
//			"00000000000000000000000000000000"
//			+ "00000000000000000000000000000000"
//			+ "00000000000000000000000000000000"
//			+ "00000000000000000000000000000000"
//			;

		public ChaCha () : base(ObscurCore.Cryptography.Ciphers.Stream.StreamCipher.ChaCha)
		{
		    SegmentedVectorTests.Add(new SegmentedVectorTestCase(
		        "[K128-IV64] Set 1, vector# 0",
		        "80000000000000000000000000000000",
		        "0000000000000000",
		        new TestVectorSegment[] {
		            new TestVectorSegment(
		                "stream[0..63]",
		                0,
		                "FBB87FBB8395E05DAA3B1D683C422046"
		                + "F913985C2AD9B23CFC06C1D8D04FF213"
		                + "D44A7A7CDB84929F915420A8A3DC58BF"
		                + "0F7ECB4B1F167BB1A5E6153FDAF4493D"
		                ),
		            new TestVectorSegment(
		                "stream[192..]",
		                192,
		                "D9485D55B8B82D792ED1EEA8E93E9BC1"
		                + "E2834AD0D9B11F3477F6E106A2F6A5F2"
		                + "EA8244D5B925B8050EAB038F58D4DF57"
		                + "7FAFD1B89359DAE508B2B10CBD6B488E"
		                ),
		            new TestVectorSegment(
		                "stream[256..]",
		                256,
		                "08661A35D6F02D3D9ACA8087F421F7C8"
		                + "A42579047D6955D937925BA21396DDD4"
		                + "74B1FC4ACCDCAA33025B4BCE817A4FBF"
		                + "3E5D07D151D7E6FE04934ED466BA4779"
		                ),
		            new TestVectorSegment(
		                "stream[448..]",
		                448,
		                "A7E16DD38BA48CCB130E5BE9740CE359"
		                + "D631E91600F85C8A5D0785A612D1D987"
		                + "90780ACDDC26B69AB106CCF6D866411D"
		                + "10637483DBF08CC5591FD8B3C87A3AE0"
		                )
		        }
		        ));

		    SegmentedVectorTests.Add(new SegmentedVectorTestCase(
		        "[K128-IV64] Set 1, vector 9",
		        "00400000000000000000000000000000",
		        "0000000000000000",
		        new TestVectorSegment[] {
		            new TestVectorSegment(
		                "stream[0..63]",
		                0,
		                "A276339F99316A913885A0A4BE870F06"
		                + "91E72B00F1B3F2239F714FE81E88E00C"
		                + "BBE52B4EBBE1EA15894E29658C4CB145"
		                + "E6F89EE4ABB045A78514482CE75AFB7C"
		                ),
		            new TestVectorSegment(
		                "stream[192..]",
		                192,
		                "0DFB9BD4F87F68DE54FBC1C6428FDEB0"
		                + "63E997BE8490C9B7A4694025D6EBA2B1"
		                + "5FE429DB82A7CAE6AAB22918E8D00449"
		                + "6FB6291467B5AE81D4E85E81D8795EBB"
		                ),
		            new TestVectorSegment(
		                "stream[256..]",
		                256,
		                "546F5BB315E7F71A46E56D4580F90889"
		                + "639A2BA528F757CF3B048738BA141AF3"
		                + "B31607CB21561BAD94721048930364F4"
		                + "B1227CFEB7CDECBA881FB44903550E68"
		                ),
		            new TestVectorSegment(
		                "stream[448..]",
		                448,
		                "6F813586E76691305A0CF048C0D8586D"
		                + "C89460207D8B230CD172398AA33D19E9"
		                + "2D24883C3A9B0BB7CD8C6B2668DB142E"
		                + "37A97948A7A01498A21110297984CD20"
		                )
		        }
		        ));

		    SegmentedVectorTests.Add(new SegmentedVectorTestCase(
		        "[K256-IV64] Set 6, vector 0",
		        "0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D",
		        "0D74DB42A91077DE",
		        new TestVectorSegment[] {
		            new TestVectorSegment(
		                "stream[0..63]",
		                0,
		                "57459975BC46799394788DE80B928387"
		                + "862985A269B9E8E77801DE9D874B3F51"
		                + "AC4610B9F9BEE8CF8CACD8B5AD0BF17D"
		                + "3DDF23FD7424887EB3F81405BD498CC3"
		                ),
		            new TestVectorSegment(
		                "stream[65472..]",
		                65472,
		                "EF9AEC58ACE7DB427DF012B2B91A0C1E"
		                + "8E4759DCE9CDB00A2BD59207357BA06C"
		                + "E02D327C7719E83D6348A6104B081DB0"
		                + "3908E5186986AE41E3AE95298BB7B713"
		                ),
		            new TestVectorSegment(
		                "stream[65536..]",
		                65536,
		                "17EF5FF454D85ABBBA280F3A94F1D26E"
		                + "950C7D5B05C4BB3A78326E0DC5731F83"
		                + "84205C32DB867D1B476CE121A0D7074B"
		                + "AA7EE90525D15300F48EC0A6624BD0AF"
		                )
		        }
		        ));

		    SegmentedVectorTests.Add(new SegmentedVectorTestCase(
		        "[K256-IV64] Set 6, vector 1",
		        "0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12",
		        "167DE44BB21980E7",
		        new TestVectorSegment[] {
		            new TestVectorSegment(
		                "stream[0..63]",
		                0,
		                "92A2508E2C4084567195F2A1005E552B"
		                + "4874EC0504A9CD5E4DAF739AB553D2E7"
		                + "83D79C5BA11E0653BEBB5C116651302E"
		                + "8D381CB728CA627B0B246E83942A2B99"
		                ),
		            new TestVectorSegment(
		                "stream[65472..]",
		                65472,
		                "E1974EC3063F7BD0CBA58B1CE34BC874"
		                + "67AAF5759B05EA46682A5D4306E5A76B"
		                + "D99A448DB8DE73AF97A73F5FBAE2C776"
		                + "35040464524CF14D7F08D4CE1220FD84"
		                ),
		            new TestVectorSegment(
		                "stream[65536..]",
		                65536,
		                "BE3436141CFD62D12FF7D852F80C1344"
		                + "81F152AD0235ECF8CA172C55CA8C031B"
		                + "2E785D773A988CA8D4BDA6FAE0E493AA"
		                + "71DCCC4C894D1F106CAC62A9FC0A9607"
		                )
		        }
		        ));
		}
	}
}

