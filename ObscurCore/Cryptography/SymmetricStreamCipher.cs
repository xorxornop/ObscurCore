namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Symmetric stream ciphers able to be used in an ObscurCore CryptoStream.
    /// </summary>
    public enum SymmetricStreamCipher
    {
        None,

        /// <summary>
        /// Stream cipher designed for fast operation in software.
        /// </summary>
        Hc128,

        /// <summary>
        /// Same as HC-128, but 256-bit key.
        /// </summary><seealso cref="Hc128"/>
        Hc256,
#if INCLUDE_ISAAC
    /// <summary>
    /// Fast, classic pseudorandom number generator and stream cipher designed by Robert J. Jenkins Jr. in 1996. 
    /// Used in UNIX for "shred" utility for securely overwriting data.
    /// </summary>
        Isaac,
#endif
        /// <summary>
        /// 128-bit key high performance software-optimised stream cipher. 
        /// eSTREAM Phase 3 candidate. Patented, but free for non-commercial use.
        /// </summary>
        Rabbit,
#if INCLUDE_RC4
    /// <summary>
    /// 40-to-2048-bit adjustible-length key stream cipher, used most famously in SSL and WEP encryption.
    /// </summary>
		Rc4,
#endif
        /// <summary>
        /// 256-bit key stream cipher. eSTREAM Phase 3 candidate. Unpatented, free for any use.
        /// </summary>
        Salsa20,

        /// <summary>
        /// 256-bit key stream cipher designed for high performance and low resource use in software. 
        /// eSTREAM Phase 3 candidate. Free for any use.
        /// </summary>
        Sosemanuk,

#if INCLUDE_VMPC
    /// <summary>
    /// Variably Modified Permutation Composition. Very simple implementation, high performance stream cipher.
    /// </summary><seealso cref="VMPC_KSA3"/>
		Vmpc,

        /// <summary>
        /// Variant of VMPC with a strengthened key setup procedure.
        /// </summary><seealso cref="VMPC"/>
        Vmpc_Ksa3
#endif
    }
}