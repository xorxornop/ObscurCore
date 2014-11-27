using Obscur.Core.DTO;

namespace Obscur.Core.Cryptography.KeyDerivation
{
    public interface IKdfFunction
    {
        /// <summary>
        /// Derives a key using the object instance configuration.
        /// </summary>
        /// <returns>The derived key.</returns>
        /// <param name="key">Pre-key material to derive working key from.</param>
        /// <param name="salt">Salt to apply in the derivation process.</param>
        byte[] DeriveKey(byte[] key, byte[] salt);
		
        /// <summary>
        /// Derives a key using the object instance configuration, but with output size override.
        /// </summary>
        /// <returns>The derived key.</returns>
        /// <param name="key">Pre-key material to derive working key from.</param>
        /// <param name="salt">Salt to apply in the derivation process.</param>
		/// <param name="outputSize">Size/length of the derived key in bytes.</param>
        byte[] DeriveKey(byte[] key, byte[] salt, int outputSize);
		
        /// <summary>
        /// Derives a key using the object instance configuration, but with output size override.
        /// </summary>
        /// <returns>The derived key.</returns>
        /// <param name="key">Pre-key material to derive working key from.</param>
        /// <param name="salt">Salt to apply in the derivation process.</param>
        /// <param name="config">Configuration to use in the KDF instance.</param>
        byte[] DeriveKey(byte[] key, byte[] salt, byte[] config);
		
        /// <summary>
        /// Derives a key using a specified configuration and output size.
        /// </summary>
        /// <returns>The derived key.</returns>
        /// <param name="key">Pre-key material to derive working key from.</param>
        /// <param name="salt">Salt to apply in the derivation process.</param>
		/// <param name="outputSize">Size/length of the derived key in bytes.</param>
        /// <param name="config">Configuration to use in the KDF instance.</param>
        byte[] DeriveKey(byte[] key, byte[] salt, int outputSize, byte[] config);

        byte[] DeriveKey(byte[] key, int outputSize, KeyDerivationConfiguration config);
    }
}