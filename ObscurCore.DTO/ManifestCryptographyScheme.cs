namespace ObscurCore.DTO
{
    /// <summary>
    /// Types of cryptography used for encrypting Manifests.
    /// </summary>
    public enum ManifestCryptographyScheme
    {
        /// <summary>
        /// Using a key known to both parties (sender and receiver).
        /// </summary>
        SymmetricOnly, 

        /// <summary>
        /// Unified Model 1 EC-hybrid (PKC-derived-key symmetric encryption) scheme.
        /// </summary>
        /// <remarks>
        /// Uses UM1 to generate a secret value, which is further derived with a KDF. 
        /// This derived secret is used as a symmetric cipher key, and optionally, for key confirmation.
        /// </remarks>
        UM1Hybrid
    }
}