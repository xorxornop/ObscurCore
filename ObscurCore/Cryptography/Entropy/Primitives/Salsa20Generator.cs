using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
    /// <summary>
    /// Generates deterministic cryptographically secure pseudorandom number sequence 
    /// using internal Salsa20 stream cipher.
    /// </summary>
    public sealed class Salsa20Generator : StreamCsprng
    {
		public Salsa20Generator(StreamCipherCsprngConfiguration config) : base(new Salsa20Engine(), config) {
			Cipher.Init(true, Config.Key, Config.Nonce);
        }

        public Salsa20Generator(byte[] config) : base(new Salsa20Engine(), config) {
			Cipher.Init(true, Config.Key, Config.Nonce);
        }
    }
}
