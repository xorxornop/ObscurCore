namespace ObscurCore.DTO
{
    /// <summary>
    /// Possible distinct types of payload item that should/can be treated differently by an application.
    /// </summary>
    public enum PayloadItemType
    {
        Binary = 0,
        Utf8,
        Utf32,
        KeyAction
    }
}