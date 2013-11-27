namespace ObscurCore.Cryptography.Entropy
{
    /// <summary>
    /// Interface that CSPRNGs conform to.
    /// </summary>
    public interface ICsprngCompatible
    {
        void GetKeystream(byte[] buffer, int offset, int length);
    }
}