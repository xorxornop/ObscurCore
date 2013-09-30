using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.Entropy
{
    [TestFixture]
    class CSPRNGTests
    {
        private const int iterations = 1000000; // 1,000,000 (1 million)

        [Test]
        public void SOSEMANUK_Int32 () {
            var generator = Source.CreateCSPRNG(CSPRNumberGenerators.SOSEMANUK, 
                SOSEMANUKGeneratorConfigurationUtility.WriteRandom());
            TimeSpan time;
            double average;

            RunTestInt32(generator, ((csprng, output) =>
                {
                    for (var i = 0; i < output.Length; i++) {
                        output[i] = csprng.NextInt();
                    }
                }),  out average, out time);

            DisplayResult(average, Int32.MaxValue, time, "Int32");
        }

        [Test]
        public void SOSEMANUK_UInt32 () {
            var generator = Source.CreateCSPRNG(CSPRNumberGenerators.SOSEMANUK, 
                SOSEMANUKGeneratorConfigurationUtility.WriteRandom());
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
            var generator = Source.CreateCSPRNG(CSPRNumberGenerators.Salsa20, 
                Salsa20GeneratorConfigurationUtility.WriteRandom());
            TimeSpan time;
            double average;

            RunTestInt32(generator, ((csprng, output) =>
                {
                    for (var i = 0; i < output.Length; i++) {
                        output[i] = csprng.NextInt();
                    }
                }),  out average, out time);

            DisplayResult(average, Int32.MaxValue, time, "Int32");
        }

        [Test]
        public void Salsa20_UInt32 () {
            var generator = Source.CreateCSPRNG(CSPRNumberGenerators.Salsa20, 
                Salsa20GeneratorConfigurationUtility.WriteRandom());
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
                ((double)iterations / timeSpan.Milliseconds) * 1000, type);
        }

        private void RunTestInt32(CSPRNG csprng, Action<CSPRNG, Int32[]> core, out double average, out TimeSpan timeSpan) {
            var output = new Int32[iterations];
            var sw = new Stopwatch();

            sw.Start();
            core(csprng, output);
            sw.Stop();

            timeSpan = sw.Elapsed;
            average = output.Average();
        }

        private void RunTestUInt32(CSPRNG csprng, Action<CSPRNG, UInt32[]> core, out double average, out TimeSpan timeSpan) {
            var output = new UInt32[iterations];
            var sw = new Stopwatch();

            sw.Start();
            core(csprng, output);
            sw.Stop();

            timeSpan = sw.Elapsed;
            average = output.Average(u => u);
        }
    }
}
