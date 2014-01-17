namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    /// Symmetric block ciphers able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum SymmetricBlockCipher
    {
        None,
        /// <summary>
        /// Very popular and well-regarded 128-bit block cipher, 128/192/256-bit key. 
        /// Restricted subset of Rijndael (which offers 128/192/256 block sizes).
        /// </summary>
        Aes,

        /// <summary>
        /// Classic block cipher, old but still good. Published 1993 by Bruce Schneier.
        /// </summary>
        Blowfish,

        /// <summary>
        /// 128-bit block cipher jointly developed by Mitsubishi and NTT. Comparable to AES.
        /// </summary>
        Camellia,

        /// <summary>
        /// Default cipher in some versions of GPG and PGP. Also known as CAST-128. 
        /// </summary><seealso cref="Cast6"/>
        Cast5,

        /// <summary>
        /// Block cipher published in June 1998. Also known as CAST-256.
        /// </summary><seealso cref="Cast5"/>
        Cast6,

        /// <summary>
        /// International Data Encryption Algorithm - patent unencumbered as of 2012. 64 bit block size.
        /// </summary>
        Idea,

        /// <summary>
        /// 128-bit block cipher. Year 2000 NESSIE entrant - not selected.
        /// </summary>
        Noekeon,

        /// <summary>
        /// 128-bit block cipher. Finalist of AES content. Derivative of RC5.
        /// </summary>
        Rc6,
        /*
		/// <summary>
		/// Block cipher. Full version (non-subset-restricted version) of AES. 
		/// Use this if the fixed block size of 128 bits of AES is unsuitable. SLOW!
		/// </summary><seealso cref="AES"/>
		Rijndael,
        */
        /// <summary>
        /// 128-bit block cipher, finalist in AES content, 2nd place after Rijndael.
        /// </summary>
        Serpent,

        /// <summary>
        /// 128-bit block cipher. Derivative of Blowfish with better security.
        /// </summary>
        Twofish
    }
}