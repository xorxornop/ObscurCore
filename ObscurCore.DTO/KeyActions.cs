namespace ObscurCore.DTO
{
    public enum KeyActions
    {
        Associate,
        Dissociate,
        /// <summary>
        /// Reserved for use. For a scheme where key state can be 
        /// verified with state at another session-state locality.
        /// </summary>
        Validate,
        /// <summary>
        /// Reserved for use. For a scheme where keys change state 
        /// deterministically at multiple session-state localities.
        /// </summary>
        Advance
    }
}