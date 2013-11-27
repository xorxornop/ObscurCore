namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    /// Parameters for AEAD-type block cipher mode of operation.
    /// </summary>
	public class AeadParameters
		: ICipherParameters
	{
		private readonly byte[] associatedText;
		private readonly byte[] nonce;
		private readonly KeyParameter key;
		private readonly int macSize;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="key">Key to be used by underlying cipher.</param>
		/// <param name="macSize">Size of MAC in bits.</param>
		/// <param name="nonce">Nonce to be used.</param>
		/// <param name="associatedText">Associated text, if any.</param>
		public AeadParameters(
			KeyParameter	key,
			int				macSize,
			byte[]			nonce,
			byte[]			associatedText)
		{
			this.key = key;
			this.nonce = nonce;
			this.macSize = macSize;
			this.associatedText = associatedText;
		}

		public virtual KeyParameter Key
		{
			get { return key; }
		}

		public virtual int MacSize
		{
			get { return macSize; }
		}

		public virtual byte[] GetAssociatedText()
		{
			return associatedText;
		}

		public virtual byte[] GetNonce()
		{
			return nonce;
		}
	}
}
