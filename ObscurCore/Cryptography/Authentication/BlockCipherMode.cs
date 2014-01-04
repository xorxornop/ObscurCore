namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    /// Symmetric block cipher modes able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum BlockCipherMode
    {
        None,

        /// <summary>
        /// Ciphertext Block Chaining. Must be used with padding scheme.
        /// </summary>
        Cbc,

        /// <summary>
        /// Counter (aka Segmented Integer Counter, SIC). Can write partial blocks.
        /// </summary>
        Ctr,

        /// <summary>
        /// Cipher Feedback. Can write partial blocks.
        /// </summary>
        Cfb,

        /// <summary>
        /// Output Feedback. Can write partial blocks.
        /// </summary>
        Ofb
    }
}