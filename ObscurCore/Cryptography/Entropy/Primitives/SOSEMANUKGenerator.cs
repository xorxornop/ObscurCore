using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
	/// <summary>
	/// Generates deterministic cryptographically secure pseudorandom number sequence 
	/// using internal Salsa20 stream cipher.
	/// </summary>
	public sealed class SOSEMANUKGenerator : CSPRNG
	{
		private readonly SOSEMANUKEngine _engine = new SOSEMANUKEngine();

		public SOSEMANUKGenerator (byte[] iv, byte[] key) {
			_engine.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
		}

		public static SOSEMANUKGenerator CreateFromConfiguration(byte[] config) {
			byte[] iv, key;
			SOSEMANUKGeneratorConfigurationUtility.Read(config, out iv, out key);
			return new SOSEMANUKGenerator(iv, key);
		}
		
		public static SOSEMANUKGenerator CreateAndEmitConfiguration(out byte[] config) {
			config = SOSEMANUKGeneratorConfigurationUtility.WriteRandom();
			return CreateFromConfiguration(config);
		}

		public override void NextBytes (byte[] buffer) {
			_engine.GetRawKeystream (buffer, 0, buffer.Length);
		}
	}
}

