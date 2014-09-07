﻿namespace ObscurCore.Cryptography.KeyAgreement
{
    /// <summary>
    ///     Named elliptic curves over F(<sub>p</sub>) from the Brainpool consortium.
    /// </summary>
    public enum BrainpoolEllipticCurve
    {
        None,

        /// <summary>
        ///     160-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP160r1,

        /// <summary>
        ///     160-bit prime field twist curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP160t1,

        /// <summary>
        ///     192-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP192r1,

        /// <summary>
        ///     192-bit prime field twist curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP192t1,

        /// <summary>
        ///     224-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP224r1,

        /// <summary>
        ///     224-bit prime field twist curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP224t1,

        /// <summary>
        ///     256-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP256r1,

        /// <summary>
        ///     256-bit prime field twist curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP256t1,

        /// <summary>
        ///     320-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP320r1,

        /// <summary>
        ///     320-bit prime field twist curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP320t1,

        /// <summary>
        ///     384-bit prime field twist curve over F(<sub>p</sub>)
        /// </summary>
        /// <remarks>
        ///     Recommended.
        /// </remarks>
        BrainpoolP384t1,

        /// <summary>
        ///     384-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP384r1,

        /// <summary>
        ///     512-bit prime field curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP512r1,

        /// <summary>
        ///     512-bit prime field twist curve over F(<sub>p</sub>)
        /// </summary>
        BrainpoolP512t1
    }
}
