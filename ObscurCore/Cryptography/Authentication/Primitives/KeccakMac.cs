using ObscurCore.Cryptography.Authentication.Primitives.SHA3;
using ObscurCore.Cryptography.Ciphers;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	/// <summary>
	/// Keccak (SHA3) algorithm implemented as a Message Authentication Code (MAC). Variable output size.
	/// </summary>
	public class KeccakMac : KeccakManaged, IMac, IMacWithSalt
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="ObscurCore.Cryptography.MACs.KeccakMac"/> class.
		/// </summary>
		/// <param name="size">Size of the MAC produced in bytes. Supported sizes are 28, 32, 48, and 64.</param>
		/// <param name="bits">Whether <paramref name="size"/> is interpreted as bits or bytes. If true, bits.</param>
		public KeccakMac (int size, bool bits) : base(size, bits)
		{
		}

		#region IMac implementation

		public void Init (ICipherParameters parameters)
		{
			byte[] key = null, salt = null;
		    var keyParameter = parameters as KeyParameter;
		    if (keyParameter != null) key = keyParameter.GetKey();
		    var parametersWithSalt = parameters as ParametersWithSalt;
		    if (parametersWithSalt != null) salt = parametersWithSalt.GetSalt();
            this.Init(key, salt);
		}

	    public int MacSize {
	        get { return DigestSize; }
	    }

	    #endregion

        /// <summary>
        /// Init the specified key and salt by performing a block update with each sequentially, respectively. 
        /// Values are not stored - therefore, if Reset is called later, and keying and/or salting is required, 
        /// Init must also be called again.
        /// </summary>
        /// <remarks>
        /// It is possible to use keys and salts with Keccak without a HMAC construction 
        /// because it does not suffer from length-extension vulnerabilities.
        /// </remarks>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        public void Init (byte[] key, byte[] salt = null) {
            if (key != null)
                BlockUpdate(key, 0, key.Length);
            if (salt != null)
                BlockUpdate(salt, 0, salt.Length);
        }
	}
}

