namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    /// Interface that a digest/hash function conforms to.
    /// </summary>
    public interface IDigest
    {
        /// <summary>
        /// Name of the digest algorithm/function.
        /// </summary>
        string AlgorithmName { get; }

		/// <summary>
		/// Size in bytes of output digest.
		/// </summary>
        int DigestSize { get; }

        /// <summary>
        /// Size in bytes of internal buffer.
        /// </summary>
        int ByteLength { get; }

        /// <summary>
        /// Update the digest with a single byte.
        /// </summary>
        /// <param name="input">Byte to update with.</param>
        void Update(byte input);

        /// <summary>
        /// Update the digest with a block of bytes.
        /// </summary>
        /// <param name="input">The byte array containing the data to update with.</param>
        /// <param name="inOff">Offset into the byte array where the data starts.</param>
        /// <param name="length">The length of the data.</param>
        void BlockUpdate(byte[] input, int inOff, int length);

        /// <summary>
        /// Close the digest, producing the final digest value, 
        /// and resetting the state of the digest.
        /// </summary>
        /// <param name="output">Array in which to place the produced digest.</param>
        /// <param name="outOff">Offset at which the digest will be copied in at.</param>
        /// <returns>Final digest value as byte array.</returns>
        int DoFinal(byte[] output, int outOff);

        /// <summary>
        /// Reset the digest back to it's initial state.
        /// </summary>
        void Reset();
    }
}
