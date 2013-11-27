using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
    /// <summary>
    /// Generates deterministic cryptographically secure pseudorandom number sequence 
    /// using internal Salsa20 stream cipher.
    /// </summary>
    public sealed class Salsa20Generator : StreamCSPRNG
    {
		public Salsa20Generator(StreamCipherCSPRNGConfiguration config) : base(new Salsa20Engine(), config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCipher.Salsa20, Config.Key,
                Config.Nonce);
            Cipher.Init(true, cp);
        }

        public Salsa20Generator(byte[] config) : base(new Salsa20Engine(), config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCipher.Salsa20, Config.Key,
                Config.Nonce);
            Cipher.Init(true, cp);
        }
    }
}
