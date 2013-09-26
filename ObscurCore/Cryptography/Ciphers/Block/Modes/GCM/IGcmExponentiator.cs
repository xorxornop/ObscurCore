namespace ObscurCore.Cryptography.Ciphers.Block.Modes.GCM
{
	public interface IGcmExponentiator
	{
		void Init(byte[] x);
		void ExponentiateX(long pow, byte[] output);
	}
}
