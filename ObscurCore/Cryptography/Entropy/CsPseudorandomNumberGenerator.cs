namespace ObscurCore.Cryptography.Entropy
{
    /// <summary>
    /// Number generators that generate deterministic, cryptographically 
    /// secure sequences of numbers that vary from set starting parameters.
    /// </summary>
    public enum CsPseudorandomNumberGenerator
    {
        /// <summary>
        /// Generator based on Salsa20 stream cipher.
        /// </summary>
        Salsa20,
        /// <summary>
        /// Generator based on SOSEMANUK stream cipher. Fast initialisation and generation.
        /// </summary>
        Sosemanuk
    }
}