using System.IO;

namespace Obscur.Core.Support
{
	/// <summary>
	/// Encode and decode byte arrays (typically from binary to 7-bit ASCII encodings).
	/// </summary>
	public interface IEncoder
	{
		int Encode(byte[] data, int off, int length, Stream outStream);

		int Decode(byte[] data, int off, int length, Stream outStream);

		int DecodeString(string data, Stream outStream);
	}
}

