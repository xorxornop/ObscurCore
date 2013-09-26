namespace ObscurCore.Cryptography.Ciphers.Block.Modes.GCM
{
	public interface IGcmMultiplier
	{
		void Init(byte[] H);
		void MultiplyH(byte[] x);
	}
}
