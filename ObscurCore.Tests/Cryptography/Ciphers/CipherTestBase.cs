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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;


using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography
{
    public abstract class CipherTestBase : IOTestBase
    {
		private static Random Rng = new Random();
		protected static byte[] CreateRandomByteArray (int lengthBits) {
			var key = new byte[lengthBits / 8];
			Rng.NextBytes(key);
			return key;
		}

		public CipherTestBase ()
		{
			DiscreteVectorTests = new List<DiscreteVectorTestCase> ();
			SegmentedVectorTests = new List<SegmentedVectorTestCase> ();
		}

		// Vector testing resources

		public List<DiscreteVectorTestCase> DiscreteVectorTests { get; private set; }

		public List<SegmentedVectorTestCase> SegmentedVectorTests { get; private set; }

		public abstract class CipherTestCase
		{
			public CipherTestCase(string name, string key, string iv, string extra = null)
			{
				this.Name = name;
				this.Key = key.HexToBinary();
				this.IV = iv.HexToBinary();
				this.Extra = extra;
			}

			public string Name { get; private set; }
			public byte[] Key { get; private set; }
			public byte[] IV { get; private set; }

			/// <summary>
			/// Extra configuration for test case where required.
			/// </summary>
			public string Extra { get; private set; }
		}


		public class DiscreteVectorTestCase : CipherTestCase
		{
			public DiscreteVectorTestCase(string name, string key, string iv, string plaintext, 
				string ciphertext, string extra = null) : base (name, key, iv, extra)
			{
				this.Plaintext = plaintext.HexToBinary();
				this.Ciphertext = ciphertext.HexToBinary();
			}

			public byte[] Plaintext { get; private set; }
			public byte[] Ciphertext { get; private set; }
		}

		public class SegmentedVectorTestCase : CipherTestCase
		{
			public SegmentedVectorTestCase(string name, string key, string iv, 
				ICollection<TestVectorSegment> segments, string extra = null) : base (name, key, iv, extra)
			{
				Segments = new List<TestVectorSegment>(segments);
			}

			public List<TestVectorSegment> Segments { get; private set; }
		}


		public class TestVectorSegment
		{
			public TestVectorSegment(string name, int offset, string ciphertext, string extra = null)
			{
				this.Name = name;
				this.Offset = offset;
				this.Ciphertext = ciphertext.HexToBinary();
				this.Extra = extra;
			}

			public string Name { get; private set; }
			public int Offset { get; private set; }
			public byte[] Ciphertext { get; private set; }

			public int Length
			{
				get { return Ciphertext.Length; }
			}

			/// <summary>
			/// Extra configuration data where required.
			/// </summary>
			public string Extra { get; private set; }
		}

		[Test]
		public void Correctness() {
			var sb = new System.Text.StringBuilder (DiscreteVectorTests.Count + " discrete vector tests ran successfully:\n\n");
			for (int i = 0; i < DiscreteVectorTests.Count; i++) {
				RunDiscreteVectorTest (i, DiscreteVectorTests [i]);
				sb.AppendLine ("> " + DiscreteVectorTests[i].Name);
			}
			sb.AppendLine ();
			sb.AppendLine (SegmentedVectorTests.Count + " segmented vector tests ran successfully:\n");
			for (int i = 0; i < SegmentedVectorTests.Count; i++) {
				RunSegmentedVectorTest (i, SegmentedVectorTests [i]);
				sb.AppendLine ("> " + SegmentedVectorTests[i].Name);
			}

			Assert.Pass (sb.ToString());
		}

		protected void RunVectorTest (int number, DiscreteVectorTestCase testCase) {
			RunDiscreteVectorTest (number, testCase);
		}

		protected abstract SymmetricCipherConfiguration GetCipherConfiguration (CipherTestCase testCase);

		protected void RunDiscreteVectorTest(int number, DiscreteVectorTestCase testCase) {
			var config = GetCipherConfiguration (testCase);
			var plaintext = testCase.Plaintext;

			byte[] ciphertext;
			using (var msCiphertext = new MemoryStream ()) {
				using (var cs = new SymmetricCipherStream(msCiphertext, true, config, testCase.Key, false)) {
					cs.Write (testCase.Plaintext, 0, testCase.Plaintext.Length);
				}
				ciphertext = msCiphertext.ToArray ();
			}

			Assert.IsTrue (testCase.Ciphertext.SequenceEqualConstantTime(ciphertext), 
				"Test #{0} (\"{1}\") failed!", number, testCase.Name);
		}

		protected void RunSegmentedVectorTest(int number, SegmentedVectorTestCase testCase) {
			var config = GetCipherConfiguration (testCase);
			byte[] plaintext = new byte[testCase.IV.Length];
			var lastSegment = testCase.Segments.Last();
			int requiredCiphertextLength = lastSegment.Offset + lastSegment.Length;
			var msCiphertext = new MemoryStream ();

			using (var cs = new SymmetricCipherStream(msCiphertext, true, config, testCase.Key, false)) {
				while (cs.BytesOut < requiredCiphertextLength) {
					cs.Write (plaintext, 0, plaintext.Length);
				}
			}

			// Now we analyse the ciphertext segment-wise

			foreach (var segment in testCase.Segments) {
				msCiphertext.Seek (segment.Offset, SeekOrigin.Begin);
				var segmentCiphertext = new byte[segment.Length];
				msCiphertext.Read (segmentCiphertext, 0, segment.Length);
				var referenceCiphertext = segment.Ciphertext;
				// Validate the segment
				Assert.IsTrue (referenceCiphertext.SequenceEqualConstantTime (segmentCiphertext), 
					"Segmented vector test #{0} (\"{1}\") failed at segment {2}!", 
					number, testCase.Name, segment.Name);
			}
		}

		// Performance testing resources (not called in this base class, but called from derived classes)

        protected void RunPerformanceTest (SymmetricCipherConfiguration config, byte[] overrideKey = null) {
			MemoryStream msInputPlaintext = LargeBinaryFile;
			byte[] key = overrideKey ?? CreateRandomByteArray (config.KeySizeBits);
			TimeSpan encryptTime, decryptTime;

			var msCiphertext = new MemoryStream();
			var sw = new Stopwatch();

			// TEST STARTS HERE

			using (var cs = new SymmetricCipherStream(msCiphertext, true, config, key, false)) {
				sw.Start();
				msInputPlaintext.CopyTo(cs, GetBufferSize());
			}
			sw.Stop();
			encryptTime = sw.Elapsed;

			var msOutputPlaintext = new MemoryStream();
			msCiphertext.Seek(0, SeekOrigin.Begin);

			sw.Reset();
			using (var cs = new SymmetricCipherStream(msCiphertext, false, config, key, false)) {
				sw.Start();
				cs.CopyTo(msOutputPlaintext, GetBufferSize());
			}
			sw.Stop();
			decryptTime = sw.Elapsed;

			// TEST ENDS HERE

			// TEST OUTPUT PLAINTEXT VALIDITY

			msInputPlaintext.Seek (0, SeekOrigin.Begin);
			msOutputPlaintext.Seek (0, SeekOrigin.Begin);
			int failurePosition;
			Assert.IsTrue (StreamsContentMatches (msInputPlaintext, msOutputPlaintext, (int)msInputPlaintext.Length, out failurePosition), 
				"Input and output plaintext does not match. First failure observed at position # " + failurePosition);

			// OUTPUT SUCCESS STATISTICS

			double encSpeed = ((double) msInputPlaintext.Length / 1048576) / encryptTime.TotalSeconds, decSpeed = 
				((double) msInputPlaintext.Length / 1048576) / decryptTime.TotalSeconds;
			Assert.Pass("{0:N0} ms ({1:N2} MB/s) : {2:N0} ms ({3:N2} MB/s)", 
				encryptTime.TotalMilliseconds, encSpeed, decryptTime.TotalMilliseconds, decSpeed);
        }

		protected static bool StreamsContentMatches (Stream a, Stream b, int length, out int failurePosition) {
			for (int i = 0; i < length; i++) {
				if (a.ReadByte() != b.ReadByte()) {
					failurePosition = i;
					return false;
				}
			}
			failurePosition = -1;
			return true;
		}
    }
}
