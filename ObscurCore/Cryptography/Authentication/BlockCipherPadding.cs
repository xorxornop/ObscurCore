namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    /// Symmetric block cipher padding types able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum BlockCipherPadding
    {
        None,

        /// <summary>
        /// ISO 10126-2 - Withdrawn! - 
        /// Random bytes added as required.
        /// </summary>
        Iso10126D2,

        /// <summary>
        /// ISO/IEC 7816-4 - 
        /// First padding byte (marking the boundary) is 0x80, rest as required are 0x00.
        /// </summary>
        Iso7816D4,

        /// <summary>
        /// Bytes added have value of number of bytes required for padding e.g if 3, 0x03-0x03-0x03
        /// </summary>
        Pkcs7,

        /// <summary>
        /// Trailing bit complement - 
        /// Padding consists of repeats of the complement of the last bit of the plaintext, e.g for 1, is 0.
        /// </summary>
        Tbc,

        /// <summary>
        /// ANSI X.923 - Zero bytes (0x00) are added as required until last padding byte; byte value is number of padding bytes added.
        /// </summary>
        X923
    }
}