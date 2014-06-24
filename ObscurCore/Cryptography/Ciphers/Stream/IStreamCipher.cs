using System;

namespace ObscurCore.Cryptography.Ciphers.Stream
{
    /// <summary>The interface that stream ciphers conform to.</summary>
    public interface IStreamCipher
    {
        /// <summary>The name of the algorithm this cipher implements.</summary>
        string AlgorithmName { get; }

        /// <summary>
        ///     The size of operation in bytes the cipher implements internally, e.g. keystream buffer.
        /// </summary>
        /// <value>The size of the internal operation in bytes.</value>
        int StateSize { get; }

        /// <summary>
        ///     Initialise the cipher.
        /// </summary>
        /// <param name="encrypting">
        ///     If <c>true</c> the cipher is initialised for encryption,
        ///     otherwise for decryption.
        /// </param>
        /// <param name="key">Key for the cipher.</param>
        /// <param name="iv">Nonce/initialisation vector for the cipher, where applicable.</param>
        /// <exception cref="ArgumentException">
        ///     If the parameter argument is invalid (e.g. incorrect length).
        /// </exception>
        void Init(bool encrypting, byte[] key, byte[] iv);

        /// <summary>
        ///     Encrypt/decrypt a single byte.
        /// </summary>
        /// <param name="input">The byte to be processed.</param>
        /// <returns>Result of processing the input byte.</returns>
        byte ReturnByte(byte input);

        /// <summary>
        ///     Encrypt/decrypt bytes from <c>input</c> and put the result into <c>output</c>.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///     The offset in <paramref name="input"/> at which the input data begins.
        /// </param>
        /// <param name="length">The number of bytes to be processed.</param>
        /// <param name="output">The output byte array.</param>
        /// <param name="outOff">
        ///     The offset in <paramref name="output"/> at which to write the output data to.
        /// </param>
        /// <exception cref="DataLengthException">
        ///     If input or output buffers are of insufficient length to read/write input/output.
        /// </exception>
        void ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff);

        /// <summary>
        ///     Reset the cipher to the same state as it was after the last init (if there was one).
        /// </summary>
        void Reset();
    }
}
