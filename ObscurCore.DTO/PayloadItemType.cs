namespace ObscurCore.DTO
{
    /// <summary>
    /// Possible distinct types of payload item that should/can be treated differently by an application.
    /// </summary>
	public enum PayloadItemType : byte
    {
        /// <summary>
        /// Binary data conforming with the ObscurCore filesystem schema.
        /// </summary>
        File,
        /// <summary>
        /// Text data capable of conforming with the ObscurCore filesystem schema (treated as a text-type <see cref="File"/>).
        /// </summary>
        Message,
        /// <summary>
        /// Value within some key-value system, that should not be treated as either <see cref="File"/> or <see cref="Message"/>.
        /// </summary>
        Value,

		KeyAction
    }
}