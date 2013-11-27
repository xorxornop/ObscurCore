using System.Diagnostics;
using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Extensions.ByteArrays;

namespace ObscurCore.Tests.Cryptography
{
    public abstract class DigestTestBase : IOTestBase
    {
        protected void RunDigestTest (HashFunction function) {
            byte[] outputHash = null;
            var sw = new Stopwatch();
            using (var outputMS = new MemoryStream()) {
                using (var macS = new HashStream(outputMS, true, function, out outputHash, false)) {
                    sw.Start();
                    LargeBinaryFile.CopyTo(macS);
                    sw.Stop();
                }
            }

            Debug.Print(outputHash.ToHexString());
            Assert.Pass("{0:N0} ms ({1:N2} MB/s)", sw.ElapsedMilliseconds, ((double) LargeBinaryFile.Length / 1048576) / sw.Elapsed.TotalSeconds);
        }
    }
}
