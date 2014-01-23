using System;

namespace ObscurCore.Cryptography.Ciphers.Stream
{
	/// <summary>The interface stream ciphers conform to.</summary>
    public interface IStreamCipher
    {
		/// <summary>The name of the algorithm this cipher implements.</summary>
		string AlgorithmName { get; }

		/// <summary>
		/// The size of operation the cipher implements internally, e.g. keystream buffer.
		/// </summary>
		/// <value>The size of the internal operation.</value>
		int StateSize { get; }

		/// <summary>
		/// Initialise the cipher.
		/// </summary>
		/// <param name="forEncryption">If true the cipher is initialised for encryption,
		/// if false for decryption.</param>
		/// <param name="parameters">The key and other data required by the cipher.</param>
		/// <exception cref="ArgumentException">
		/// If the parameter argument is invalid (e.g. incorrect length).
		/// </exception>
		void Init (bool encrypting, byte[] key, byte[] iv);

		/// <summary>
		/// Encrypt/Decrypt a single byte.
		/// </summary>
		/// <param name="input">The byte to be processed.</param>
		/// <returns>Result of processing the input byte.</returns>
        byte ReturnByte(byte input);

		/// <summary>
		/// Process bytes from <c>input</c> and put the result into <c>output</c>.
		/// </summary>
		/// <param name="input">The input byte array.</param>
		/// <param name="inOff">
		/// The offset into <paramref>input</paramref> where the data to be processed starts.
		/// </param>
		/// <param name="length">The number of bytes to be processed.</param>
		/// <param name="output">The output buffer the processed bytes go into.</param>
		/// <param name="outOff">
		/// The offset into <paramref>output</paramref> the processed data starts at.
		/// </param>
		/// <exception cref="DataLengthException">
		/// If input or output buffers are of insufficient length to read/write input/output.
		/// </exception>
        void ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff);

		/// <summary>
		/// Reset the cipher to the same state as it was after the last init (if there was one).
		/// </summary>
		void Reset();
    }
}
