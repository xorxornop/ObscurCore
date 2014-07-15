using System.Diagnostics;
using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography.Authentication;

namespace ObscurCore.Tests.Cryptography
{
    public abstract class DigestTestBase : IOTestBase
    {
        protected void RunDigestTest (HashFunction function) {
            byte[] outputHash;
            var sw = new Stopwatch();
            using (var output = new MemoryStream((int)LargeBinaryFile.Length)) {
                using (var macS = new HashStream(output, true, function, out outputHash, false)) {
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
