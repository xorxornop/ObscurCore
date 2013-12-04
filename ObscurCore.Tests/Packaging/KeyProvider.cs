using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging
{
    class KeyProvider : IKeyProvider
    {
        public KeyProvider() {
            var symKeys = new List<byte[]>();
            for (int i = 0; i < 5; i++) {
                var newKey = new byte[16];
                StratCom.EntropySource.NextBytes(newKey);
                symKeys.Add(newKey);
            }
            SymmetricKeys = symKeys;
        }

        /// <summary>
        /// Symmetric key(s) to decrypt a manifest with.
        /// </summary>
        public IEnumerable<byte[]> SymmetricKeys { get; private set; }

        /// <summary>
        /// EC key(s) to decrypt the manifest with.
        /// </summary>
        public IEnumerable<EcKeyConfiguration> EcSenderKeys { get; private set; }

        /// <summary>
        /// EC key(s) to decrypt the manifest with.
        /// </summary>
        public IEnumerable<EcKeyConfiguration> EcReceiverKeys { get; private set; }

        /// <summary>
        /// Curve25519 key(s) to decrypt a manifest with.
        /// </summary>
        public IEnumerable<byte[]> Curve25519SenderKeys { get; private set; }

        /// <summary>
        /// Curve25519 EC public key(s) to decrypt the manifest with.
        /// </summary>
        public IEnumerable<byte[]> Curve25519ReceiverKeys { get; private set; }
    }
}
