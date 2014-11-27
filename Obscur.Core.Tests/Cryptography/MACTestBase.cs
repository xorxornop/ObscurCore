using System.Diagnostics;
using System.IO;
using NUnit.Framework;
using Obscur.Core;
using Obscur.Core.Cryptography.Authentication;

namespace ObscurCore.Tests.Cryptography
{
    public abstract class MacTestBase : IOTestBase
    {
        protected byte[] Key { get; set; }
        protected byte[] Salt { get; set; }

        protected static byte[] CreateRandomBytes (int lengthBits) {
            var bytes = new byte[lengthBits / 8];
            StratCom.EntropySupplier.NextBytes(bytes);
            return bytes;
        }

        protected void SetRandomFixtureParameters(int lengthBits) {
            Key = CreateRandomBytes(lengthBits);
            Salt = CreateRandomBytes(lengthBits);
        }

		protected void RunMacTest (MacFunction function, byte[] config = null, byte[] nonce = null, byte[] overrideKey = null, byte[] overrideSalt = null) {
            byte[] outputMac;
            var sw = new Stopwatch();
            using (var output = new MemoryStream((int)LargeBinaryFile.Length)) {
				using (var macS = new MacStream(output, true, function, out outputMac, overrideKey ?? Key, overrideSalt ?? Salt, config, nonce, false)) {
                    sw.Start();
                    LargeBinaryFile.CopyTo(macS);
                    sw.Stop();
                }
            }

            Debug.Print(outputMac.ToHexString());
            Assert.Pass("{0:N0} ms ({1:N2} MB/s)", sw.ElapsedMilliseconds, ((double) LargeBinaryFile.Length / 1048576) / sw.Elapsed.TotalSeconds);
        }
    }
}
