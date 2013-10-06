namespace ObscurCore.DTO
{
    /// <summary>
    /// Defines common data found in manifest cryptography scheme configurations.
    /// </summary>
    public interface IManifestCryptographySchemeConfiguration
    {
        KeyDerivationConfiguration KeyDerivation { get; set; }
        SymmetricCipherConfiguration SymmetricCipher { get; set; }
        //string GetContextInvariantIdentifier ();
    }
}
