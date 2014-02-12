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
using System.Diagnostics;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.Entropy
{
    [TestFixture]
    class CsprngTests
    {
		private const int Iterations = 10000000; // 10,000,000 (10 million)

        [Test]
        public void SOSEMANUK_Int32 () {
            var generator = new SosemanukGenerator(Source.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk));
            TimeSpan time;
            double average;

            RunTestInt32(generator, ((csprng, output) =>
                {
                    for (var i = 0; i < output.Length; i++) {
						output[i] = csprng.Next();
                    }
                }),  out average, out time);

            DisplayResult(average, Int32.MaxValue, time, "Int32");
        }

        [Test]
        public void SOSEMANUK_UInt32 () {
            var generator = new SosemanukGenerator(Source.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Sosemanuk));
            TimeSpan time;
            double average;

            RunTestUInt32(generator, ((csprng, output) =>
                {
                    for (var i = 0; i < output.Length; i++) {
                        output[i] = csprng.NextUInt32();
                    }
                }),  out average, out time);

            DisplayResult(average, UInt32.MaxValue, time, "UInt32");
        }

        [Test]
        public void Salsa20_Int32 () {
            var generator = new Salsa20Generator(Source.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Salsa20));
            TimeSpan time;
            double average;

            RunTestInt32(generator, ((csprng, output) =>
                {
                    for (var i = 0; i < output.Length; i++) {
						output[i] = csprng.Next();
                    }
                }),  out average, out time);

            DisplayResult(average, Int32.MaxValue, time, "Int32");
        }

        [Test]
        public void Salsa20_UInt32 () {
            var generator = new Salsa20Generator(Source.CreateStreamCipherCsprngConfiguration(
                    CsPseudorandomNumberGenerator.Salsa20));
            TimeSpan time;
            double average;

            RunTestUInt32(generator, ((csprng, output) =>
                {
                    for (var i = 0; i < output.Length; i++) {
                        output[i] = csprng.NextUInt32();
                    }
                }),  out average, out time);

            DisplayResult(average, UInt32.MaxValue, time, "UInt32");
        }

        private static void DisplayResult(double average, long range, TimeSpan timeSpan, string type) {
            Assert.Pass("<> {0:P4} @ {1:N2} {2}/sec.", Math.Abs(1 - ((decimal)(range / 2.0) / (decimal)average)), 
                ((double)Iterations / timeSpan.Milliseconds) * 1000, type);
        }

        private void RunTestInt32(Csprng csprng, Action<Csprng, Int32[]> core, out double average, out TimeSpan timeSpan) {
            var output = new Int32[Iterations];
            var sw = new Stopwatch();

            sw.Start();
            core(csprng, output);
            sw.Stop();

            timeSpan = sw.Elapsed;
            average = output.Average();
        }

        private void RunTestUInt32(Csprng csprng, Action<Csprng, UInt32[]> core, out double average, out TimeSpan timeSpan) {
            var output = new UInt32[Iterations];
            var sw = new Stopwatch();

            sw.Start();
            core(csprng, output);
            sw.Stop();

            timeSpan = sw.Elapsed;
            average = output.Average(u => u);
        }
    }
}
