namespace ObscurCore
{
    /// <summary>
    /// Policy for toleration of nonce reuse in a cryptographic scheme.
    /// </summary>
    /// <remarks>
    /// Reuse of a nonce/IV in a scheme that does not allow for it can result in total security failure.
    /// </remarks>
    public enum NonceReusePolicy
    {
        NotApplicable = 0,
        /// <summary>
        /// Nonce reuse may result in total or partial loss of security properties.
        /// </summary>
        NotAllowed,
        /// <summary>
        /// Construction of operation mode allows nonce reuse without catastrophic security loss, 
        /// but better security properties will be obtained by ensuring a new nonce is used each time.
        /// </summary>
        Allowed
    }
}