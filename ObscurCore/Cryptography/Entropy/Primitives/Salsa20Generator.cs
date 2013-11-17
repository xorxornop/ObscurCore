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
        private readonly Salsa20Engine _engine = new Salsa20Engine();
		
		public Salsa20Generator(StreamCipherCSPRNGConfiguration config) : base(config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCiphers.Salsa20, Config.Key,
                Config.Nonce);
            _engine.Init(true, cp);
        }

        public Salsa20Generator(byte[] config) : base(config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCiphers.Salsa20, Config.Key,
                Config.Nonce);
            _engine.Init(true, cp);
        }

        public override void NextBytes (byte[] buffer) {
            _engine.ProcessBytes(new byte[buffer.Length], 0, buffer.Length, buffer, 0);
        }
    }
}
