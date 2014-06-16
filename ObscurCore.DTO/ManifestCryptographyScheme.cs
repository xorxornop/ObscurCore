namespace ObscurCore.DTO
{
    /// <summary>
    /// Types of cryptography used for encrypting Manifests.
    /// </summary>
    public enum ManifestCryptographyScheme
    {
        None,

        /// <summary>
        /// A key known to both parties (sender and recipient) is used by a KDF to generate cipher and MAC keys.
        /// </summary>
        SymmetricOnly, 

        /// <summary>
        /// Unified Model 1-pass EC-hybrid (PKC-derived-keyed symmetric encryption) scheme.
        /// </summary>
        /// <remarks>
        /// Uses UM1 public key scheme to generate a shared secret 
        /// (sender and recipient derive an identical value from their public and private keys, 
        /// and the ephemeral, one-use UM1 public key), which is used by a KDF to generate symmetric cipher and MAC keys.
        /// </remarks>
        Um1Hybrid
    }
}