namespace ObscurCore.DTO
{
    /// <summary>
    /// Possible distinct types of payload item that should/can be treated differently by an application.
    /// </summary>
	public enum PayloadItemType : byte
    {
        Binary = 0,
		Utf8 = 100,
		Utf32 = 110,
		KeyAction = 200
    }
}