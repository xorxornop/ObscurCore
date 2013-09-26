using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
    /// <summary>
    /// Generates deterministic cryptographically secure pseudorandom number sequence 
    /// using internal Salsa20 stream cipher.
    /// </summary>
    public sealed class Salsa20Generator : CSPRNG
    {
        private readonly Salsa20Engine _engine = new Salsa20Engine();

        public Salsa20Generator (byte[] iv, byte[] key) {
            _engine.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
        }
		
		public static Salsa20Generator CreateFromConfiguration(byte[] config) {
			byte[] iv, key;
			Salsa20GeneratorConfigurationUtility.Read(config, out iv, out key);
			return new Salsa20Generator(iv, key);
		}
		
		public static Salsa20Generator CreateAndEmitConfiguration(out byte[] config) {
			config = Salsa20GeneratorConfigurationUtility.WriteRandom();
			return CreateFromConfiguration(config);
		}

        public override void NextBytes (byte[] buffer) {
            _engine.ProcessBytes(new byte[buffer.Length], 0, buffer.Length, buffer, 0);
        }
    }
}
