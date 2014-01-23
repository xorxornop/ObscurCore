using System;

namespace ObscurCore.Support
{
	public class UrlBase64Encoder
		: Base64Encoder
	{
		public UrlBase64Encoder()
		{
			encodingTable[encodingTable.Length - 2] = (byte) '-';
			encodingTable[encodingTable.Length - 1] = (byte) '_';
			padding = (byte) '.';
			// we must re-create the decoding table with the new encoded values.
			InitialiseDecodingTable();
		}
	}
}

