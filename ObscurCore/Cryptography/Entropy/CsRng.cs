

using ObscurCore.Support.Entropy;

namespace ObscurCore.Cryptography.Entropy
{
    /// <summary>
    /// Base class for cryptographically-secure random number generators (CSRNG).
    /// </summary>
    public abstract class CsRng : Rng
    {
        /// <summary>Add more seed material to the generator.</summary>
        /// <param name="seed">A byte array to be mixed into the generator's state.</param>
        public abstract void AddSeedMaterial(byte[] seed);
    }
}
