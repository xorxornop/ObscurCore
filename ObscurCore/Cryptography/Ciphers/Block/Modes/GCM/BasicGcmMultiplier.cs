namespace ObscurCore.Cryptography.Ciphers.Block.Modes.GCM
{
	public class BasicGcmMultiplier
		: IGcmMultiplier
	{
		private byte[] H;

		public void Init(byte[] H)
		{
			this.H = (byte[])H.Clone();
		}

		public void MultiplyH(byte[] x)
		{
			GcmUtilities.Multiply(x, H);
		}
	}
}
