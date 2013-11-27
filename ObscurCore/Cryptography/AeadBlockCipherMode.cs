namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Symmetric authenticated encryption authenticated decryption (AEAD) block cipher modes able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum AeadBlockCipherMode
    {
        None,

        /// <summary>
        /// Galois/Counter Mode. Highly efficient, good performance. Combines CTR mode with integral Galois field MAC scheme. 
        /// </summary>
        Gcm,

        /// <summary>
        /// Counter with OMAC, implemented with CMAC. OMAC authentication uses same cipher as encryption/decryption cipher.
        /// </summary>
        /// <see cref="http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf"/><seealso cref="http://en.wikipedia.org/wiki/CMAC"/>
        Eax
    }
}