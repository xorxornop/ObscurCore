using ObscurCore.Cryptography.Ciphers.Stream.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
	/// <summary>
	/// Generates deterministic cryptographically secure pseudorandom number sequence 
	/// using internal Salsa20 stream cipher.
	/// </summary>
	public sealed class SOSEMANUKGenerator : StreamCSPRNG
	{
		private readonly SOSEMANUKEngine _engine = new SOSEMANUKEngine();

        public SOSEMANUKGenerator(StreamCipherCSPRNGConfiguration config) : base(config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCiphers.SOSEMANUK, Config.Key,
                Config.Nonce);
            _engine.Init(true, cp);
        }

        public SOSEMANUKGenerator(byte[] config) : base(config) {
            var cp = Source.CreateStreamCipherParameters(SymmetricStreamCiphers.SOSEMANUK, Config.Key,
                Config.Nonce);
            _engine.Init(true, cp);
        }

	    public override void NextBytes (byte[] buffer) {
			_engine.GetRawKeystream (buffer, 0, buffer.Length);
		}
	}
}

