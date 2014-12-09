#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using NUnit.Framework;
using Obscur.Core.Cryptography.Authentication;

namespace Obscur.Core.Tests.Cryptography
{
    public abstract class DigestTestBase : IOTestBase
    {
        protected readonly HashFunction Hash;

        protected DigestTestBase(HashFunction hashFEnum)
        {
            Hash = hashFEnum;
            DiscreteVectorTests = new List<DiscreteVectorDigestTestCase>();
        }

        public List<DiscreteVectorDigestTestCase> DiscreteVectorTests { get; private set; }

        [Test]
        public void Correctness()
        {
            Assume.That(DiscreteVectorTests != null && DiscreteVectorTests.Count > 0, "No tests to run.");

            var sb = new StringBuilder(DiscreteVectorTests.Count + " discrete vector tests ran successfully.\n\n");

            for (int i = 0; i < DiscreteVectorTests.Count; i++) {
                RunDiscreteVectorTest(i, DiscreteVectorTests[i]);
                if (String.IsNullOrEmpty(DiscreteVectorTests[i].Name) == false) {
                    sb.AppendLine("> " + DiscreteVectorTests[i].Name);
                }
            }
            Assert.Pass(sb.ToString());
        }

        protected void RunDiscreteVectorTest(int number, DiscreteVectorDigestTestCase testCase)
        {
            var hashFunctionEnum = testCase.Primitive;

            IHash authenticator = AuthenticatorFactory.CreateHashPrimitive(hashFunctionEnum);
            authenticator.BlockUpdate(testCase.Message, 0, testCase.Message.Length);
            var output = new byte[authenticator.OutputSize];
            authenticator.DoFinal(output, 0);

            Assert.IsTrue(testCase.Output.SequenceEqualShortCircuiting(output),
                "Test #{0} (\"{1}\") failed!", number, testCase.Name);
        }

        [Test]
        public void StreamingPerformance()
        {
            RunPerformanceTest(Hash);
        }

        protected void RunPerformanceTest(HashFunction function)
        {
            MemoryStream msInputPlaintext = LargeBinaryFile;
            var sw = new Stopwatch();

            byte[] outputHash;
            using (var output = new MemoryStream((int) LargeBinaryFile.Length)) {
                using (var macS = new HashStream(output, true, function, out outputHash, false)) {
                    sw.Start();
                    msInputPlaintext.CopyTo(macS);
                }
                sw.Stop();
            }

            Debug.Print(outputHash.ToHexString());
            Assert.Pass("{0:N0} ms ({1:N2} MB/s)", sw.ElapsedMilliseconds,
                ((double) LargeBinaryFile.Length / 1048576) / sw.Elapsed.TotalSeconds);
        }

        #region Nested type: DigestTestCase

        public abstract class DigestTestCase
        {
            public DigestTestCase(string name, HashFunction primitive, string extra = null)
            {
                this.Name = name ?? "";
                this.Primitive = primitive;
                this.Extra = extra;
            }

            public string Name { get; private set; }

            public HashFunction Primitive { get; private set; }

            /// <summary>
            ///     Extra configuration for test case where required.
            /// </summary>
            public string Extra { get; private set; }
        }

        #endregion

        #region Nested type: DiscreteVectorDigestTestCase

        public class DiscreteVectorDigestTestCase : DigestTestCase
        {
            public DiscreteVectorDigestTestCase(string name, HashFunction primitive, string message,
                                          string output, string extra = null)
                : base(name, primitive, extra)
            {
                this.Message = ToByteArray(message);
                this.Output = output.HexToBinary();
            }

            public DiscreteVectorDigestTestCase(string name, HashFunction primitive, byte[] message,
                                          byte[] output, string extra = null)
                : base(name, primitive, extra)
            {
                this.Message = message;
                this.Output = output;
            }

            public byte[] Message { get; private set; }
            public byte[] Output { get; private set; }

            protected internal static byte[] ToByteArray(string input)
            {
                var bytes = new byte[input.Length];
                for (int i = 0; i != bytes.Length; i++) {
                    bytes[i] = (byte)input[i];
                }
                return bytes;
            }
        }

        #endregion
    }
}
