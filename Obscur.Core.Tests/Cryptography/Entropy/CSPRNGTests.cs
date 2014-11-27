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
using Obscur.Core;
using Obscur.Core.Cryptography.Ciphers;
using Obscur.Core.Cryptography.Ciphers.Stream;
using Obscur.Core.Cryptography.Entropy;
using Obscur.Core.Cryptography.Entropy.Primitives;

namespace ObscurCore.Tests.Cryptography.Entropy
{
    [TestFixture]
    class CsprngTests
    {
		private const int Iterations = 10000000; // 10,000,000 (10 million)

        private static StreamCsPrng GetEngine(CsPseudorandomNumberGenerator cipher)
        {
            var config = CsPrngFactory.CreateStreamCipherCsprngConfiguration(cipher);
            var engine = CipherFactory.CreateStreamCipher(config.CipherName.ToEnum<StreamCipher>());

            return new StreamCsPrng(engine, config.Key, config.Nonce);
        }

        [Test]
        public void SOSEMANUK_Int32 ()
        {
            var generator = GetEngine(CsPseudorandomNumberGenerator.Sosemanuk);
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
            var generator = GetEngine(CsPseudorandomNumberGenerator.Sosemanuk);
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
            var generator = GetEngine(CsPseudorandomNumberGenerator.Salsa20);
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
            var generator = GetEngine(CsPseudorandomNumberGenerator.Salsa20);
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
        public void Rabbit_Int32()
        {
            var generator = GetEngine(CsPseudorandomNumberGenerator.Rabbit);
            TimeSpan time;
            double average;

            RunTestInt32(generator, ((csprng, output) =>
            {
                for (var i = 0; i < output.Length; i++) {
                    output[i] = csprng.Next();
                }
            }), out average, out time);

            DisplayResult(average, Int32.MaxValue, time, "Int32");
        }

        [Test]
        public void Rabbit_UInt32()
        {
            var generator = GetEngine(CsPseudorandomNumberGenerator.Rabbit);
            TimeSpan time;
            double average;

            RunTestUInt32(generator, ((csprng, output) =>
            {
                for (var i = 0; i < output.Length; i++) {
                    output[i] = csprng.NextUInt32();
                }
            }), out average, out time);

            DisplayResult(average, UInt32.MaxValue, time, "UInt32");
        }

        private static void DisplayResult(double average, long range, TimeSpan timeSpan, string type) {
            Assert.Pass("<> {0:P4} @ {1:N2} {2}/sec.", Math.Abs(1 - ((decimal)(range / 2.0) / (decimal)average)), 
                ((double)Iterations / timeSpan.Milliseconds) * 1000, type);
        }

        private void RunTestInt32(CsPrng csprng, Action<CsPrng, Int32[]> core, out double average, out TimeSpan timeSpan)
        {
            var output = new Int32[Iterations];
            var sw = new Stopwatch();

            sw.Start();
            core(csprng, output);
            sw.Stop();

            timeSpan = sw.Elapsed;
            average = output.Average();
        }

        private void RunTestUInt32(CsPrng csprng, Action<CsPrng, UInt32[]> core, out double average, out TimeSpan timeSpan)
        {
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
