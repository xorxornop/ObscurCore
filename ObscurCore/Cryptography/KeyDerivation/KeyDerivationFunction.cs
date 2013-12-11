namespace ObscurCore.Cryptography.KeyDerivation
{
    /// <summary>
    /// Key derivation functions that transform key input material with added salt to increase attack difficulty.
    /// </summary>
    public enum KeyDerivationFunction
    {
        None,
        /// <summary>
        /// Iterative hashing derivation function designed to increase computation time and hence expense to attackers.
        /// </summary>
        Pbkdf2,
        /// <summary>
        /// Memory-hard iterative derivation function designed to be very expensive to implement and execute in attack hardware.
        /// </summary>
        Scrypt
    }
}