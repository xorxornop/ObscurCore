using System;
using System.Diagnostics;
using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Extensions.ByteArrays;

namespace ObscurCore.Tests.Cryptography
{
    public abstract class MACTestBase : IOTestBase
    {
        protected byte[] Key { get; set; }
        protected byte[] Salt { get; private set; }

        protected static byte[] CreateRandomBytes (int lengthBits) {
            var bytes = new byte[lengthBits / 8];
            var rng = new Random();
            rng.NextBytes(bytes);
            return bytes;
        }

        protected void SetRandomFixtureParameters(int lengthBits) {
            Key = CreateRandomBytes(lengthBits);
            Salt = CreateRandomBytes(lengthBits);
        }

        protected void RunMACTest (MacFunction function, byte[] config = null, byte[] overrideKey = null, byte[] overrideSalt = null) {
            byte[] outputMAC;
            var sw = new Stopwatch();
            using (var outputMS = new MemoryStream()) {
                using (var macS = new MacStream(outputMS, true, function, out outputMAC, overrideKey ?? Key, overrideSalt ?? Salt, config, false)) {
                    sw.Start();
                    LargeBinaryFile.CopyTo(macS);
                    sw.Stop();
                }
            }

            Debug.Print(outputMAC.ToHexString());
            Assert.Pass("{0:N0} ms ({1:N2} MB/s)", sw.ElapsedMilliseconds, ((double) LargeBinaryFile.Length / 1048576) / sw.Elapsed.TotalSeconds);
        }
    }
}
