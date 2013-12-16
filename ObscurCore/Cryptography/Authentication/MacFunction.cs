namespace ObscurCore.Cryptography.Authentication
{
    /// <summary>
    /// MAC functions supported for use in a MACStream. Used to verify data integrity and authenticity.
    /// </summary>
    public enum MacFunction
    {
        /// <summary>
        /// 64-bit platform & software optimised, fast. Supports additional salt and tag inputs. 
        /// Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B256,
        /// <summary>
        /// 64-bit platform & software optimised, fast. Supports additional salt and tag inputs. 
        /// Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B384,
        /// <summary>
        /// 64-bit platform & software optimised, fast. Supports additional salt and tag inputs. 
        /// Derivative of BLAKE, a SHA3 competition finalist - 2nd place.
        /// </summary>
        Blake2B512,
        /// <summary>
        /// Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction. 
        /// Supports additional salt parameter.
        /// </summary>
        Keccak224,
        /// <summary>
        /// Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction. 
        /// Supports additional salt parameter.
        /// </summary>
        Keccak256,
        /// <summary>
        /// Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction. 
        /// Supports additional salt parameter.
        /// </summary>
        Keccak384,
        /// <summary>
        /// Winner of the SHA3 hash function competition selection. Innovative 'Sponge' construction. 
        /// Supports additional salt parameter.
        /// </summary>
        Keccak512,

		Poly1305,

        /// <summary>
        /// Also called OMAC1. 
        /// As the name suggests, uses a (configurable) symmetric block cipher as the core of the primitive.
        /// </summary>
        Cmac,

        /// <summary>
        /// Hash-based MAC. 
        /// As the name suggests, uses a (configurable) hash function as the core of the primitive.
        /// </summary>
        Hmac
    }
}