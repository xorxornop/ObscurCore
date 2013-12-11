using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
	/// <summary>
	/// Generates deterministic cryptographically secure pseudorandom number sequence 
	/// using internal Salsa20 stream cipher.
	/// </summary>
	public sealed class SosemanukGenerator : StreamCsprng
	{
        public SosemanukGenerator(StreamCipherCsprngConfiguration config) : base(new SosemanukEngine(), config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCipher.Sosemanuk, Config.Key,
                Config.Nonce);
            Cipher.Init(true, cp);
        }

        public SosemanukGenerator(byte[] config) : base(new SosemanukEngine(), config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCipher.Sosemanuk, Config.Key,
                Config.Nonce);
            Cipher.Init(true, cp);
        }
	}
}

