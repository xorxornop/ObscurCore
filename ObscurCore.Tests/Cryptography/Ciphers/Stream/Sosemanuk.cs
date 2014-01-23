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
	public class Sosemanuk : StreamCipherTestBase
	{
		private static readonly string DiscretePlaintext = "00000000000000000000000000000000" + 
		                                                   "00000000000000000000000000000000" + 
		                                                   "00000000000000000000000000000000" + 
		                                                   "00000000000000000000000000000000";

		public Sosemanuk () : base(ObscurCore.Cryptography.Ciphers.Stream.SymmetricStreamCipher.Sosemanuk)
		{
			// http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/sosemanuk/unverified.test-vectors?rev=108&view=markup

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"Set 1, vector# 0",
				"80000000000000000000000000000000" +
				"00000000000000000000000000000000",
				"00000000000000000000000000000000",
				DiscretePlaintext,
				"1782FABFF497A0E89E16E1BCF22F0FE8" +
				"AA8C566D293AA35B2425E4F26E31C3E7" +
				"701C08A0D614AF3D3861A7DFF7D6A38A" +
				"0EFE84A29FADF68D390A3D15B75C972D"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"Set 2, vector# 63",
				"3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F",
				"00000000000000000000000000000000",
				DiscretePlaintext,
				"7D755F30A2B747A50D7D28147EDF0B3E" +
				"3FAB6856A7373C7306C00D1D40769693" +
				"54D7AB4343C0115E7839502C5C699ED0" +
				"6DB119968AEBFD08D8B968A7161D613F"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"Set 2, vector# 90",
				"5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A" +
				"5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A",
				"00000000000000000000000000000000",
				DiscretePlaintext,
				"F5D7D72686322D1751AFD16A1DD98282" +
				"D2B9A1EE0C305DF52F86AE1B831E90C2" +
				"2E2DE089CEE656A992736385D9135B82" +
				"3B3611098674BF820986A4342B89ABF7"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"Set 3, vector# 135",
				"8788898A8B8C8D8E8F90919293949596" +
				"9798999A9B9C9D9E9FA0A1A2A3A4",
				"00000000000000000000000000000000",
				DiscretePlaintext,
				"9D7EE5A10BBB0756D66B8DAA5AE08F41" +
				"B05C9E7C6B13532EAA81F224282B61C6" +
				"6DEEE5AF6251DB26C49B865C5AD4250A" +
				"E89787FC86C35409CF2986CF820293AA"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"Set 3, vector# 207",
				"CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE" +
				"DFE0E1E2E3E4E5E6E7E8E9EAEBECEDEE",
				"00000000000000000000000000000000",
				DiscretePlaintext,
				"F028923659C6C0A17065E013368D93EB" +
				"CF2F4FD892B6E27E104EF0A2605708EA" +
				"26336AE966D5058BC144F7954FE2FC3C" +
				"258F00734AA5BEC8281814B746197084"
			));

			DiscreteVectorTests.Add (new DiscreteVectorTestCase (
				"Set 6, vector# 3",
				"0F62B5085BAE0154A7FA4DA0F34699EC" +
				"3F92E5388BDE3184D72A7DD02376C91C",
				"288FF65DC42B92F960C72E95FC63CA31",
				DiscretePlaintext,
				"1FC4F2E266B21C24FDDB3492D40A3FA6" +
				"DE32CDF13908511E84420ABDFA1D3B0F" +
				"EC600F83409C57CBE0394B90CDB1D759" +
				"243EFD8B8E2AB7BC453A8D8A3515183E"
			));

			SegmentedVectorTests.Add (new SegmentedVectorTestCase (
				"Set 4, vector# 0",
				"0053A6F94C9FF24598EB",
				"00000000000000000000",
				new TestVectorSegment[] {
					new TestVectorSegment (
						"stream[0..63]",
						0,
						"31DC3AB92FE285475993D3C89751303E" +
						"D0CFFF1EC11831B14AE5A9BD87D91C09" +
						"998739800A4FAA987CB15679703E8C89" +
						"F47EF436F24747DBD2C4800C91E34DA2"
					),
					new TestVectorSegment (
						"stream[65472..65535]",
						65472,
						"7099E13547B5BE4CC753D2D1C2BF6DFB" +
						"C96AACCC5BD513159B1F24AA62679DF0" +
						"92F1ADDC91D55ECF2A4D0B71FF2B41D8" +
						"D969E38334566B35D7DE3224854452C7"
					),
					new TestVectorSegment (
						"stream[65536..65599]",
						65536,
						"7DC4EB2C9F315486AD89DDA5F0C5059C" +
						"67D1312EA593D625A164CC12F6B57F4C" +
						"6A824EC7FF4A830DE5066A6F659D841C" +
						"D7F7A9180B716CA49C6DB5CBC947E438"
					),
					new TestVectorSegment (
						"stream[131008..131071]",
						131008,
						"4030D1E317EBF9F6356B65AEB792E0AF" +
						"CEA4E47DD37CEA8CF99DEC03C3325EB3" +
						"AD92FC7E5054FD9AA76E1014ED751418" +
						"6C9CE7AE27A231A5B6608FAE0535823E"
					)
				}
			));

			SegmentedVectorTests.Add (new SegmentedVectorTestCase (
				"Set 5, vector# 0",
				"00000000000000000000000000000000" +
				"00000000000000000000000000000000",
				"80000000000000000000000000000000",
				new TestVectorSegment[] {
					new TestVectorSegment (
						"stream[0..63]",
						0,
						"F847D7FF5426BEF5882BD2D0717494AF" +
						"A9B7BC922915808057581BA9E35E3B7B" +
						"DAC3FC878D278FE5D145DBB71B6B16A6" +
						"134475266239B99D04E512982B4113B8"
					),
					new TestVectorSegment (
						"stream[192..255]",
						192,
						"55325FF9CD42636F007F0AC8B024380C" +
						"1480FA84D633FCEB0569A42B754A74CE" +
						"22B0D3D9D0B12C365F919884CE41A478" +
						"D8AF818D6C48E3A6F6D27BF16577F587"
					),
					new TestVectorSegment (
						"stream[256..319]",
						256,
						"614100AA1578E378424FCA648612022A" +
						"4A38D0A60A934F48328B8F0999061533" +
						"3D80C7BDB76A2C9F52CE46AE5D35CA69" +
						"A7554632DD034C9184C158376C2612D3"
					),
					new TestVectorSegment (
						"stream[448..511]",
						448,
						"1EF32C44CD8D7ABD0CF6CECECCC2EBC5" +
						"C3D26EAEDE130C00EC3044127922B39F" +
						"375170D3F4835808F75188276EB3AE1F" +
						"93690F92FA6290D1D01A72840727CA0B"
					)
				}
			));
		}
	}
}

