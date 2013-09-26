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

    /// <summary>
    /// Defines common functions and properties for asymmetric cryptographic schemes.
    /// </summary>
    public interface IAsymmetricCryptographyScheme
    {
        string GetContextInvariantIdentifier ();
    }

}
