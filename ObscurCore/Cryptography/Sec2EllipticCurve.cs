namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Named elliptic curves from SEC2 (Standards for Efficient Cryptography 2)
    /// </summary>
    public enum Sec2EllipticCurve
    {
        None,

        //Sect163k1,

        /// <summary>
        /// 163-bit curve over F(2m)
        /// </summary>
        Sect163r2,

        /// <summary>
        /// 192-bit Koblitz curve over F(p)
        /// </summary>
        Secp192k1,

        /// <summary>
        /// 192-bit curve over F(p)
        /// </summary>
        Secp192r1,

        /// <summary>
        /// 224-bit Koblitz curve over F(p)
        /// </summary>
        Secp224k1,

        /// <summary>
        /// 224-bit curve over F(p)
        /// </summary>
        Secp224r1,

        //Sect233k1,

        /// <summary>
        /// 233-bit curve over F(2m)
        /// </summary>
        Sect233r1,

        /// <summary>
        /// 224-bit Koblitz curve over F(p)
        /// </summary>
        Secp256k1,

        /// <summary>
        /// 256-bit curve over F(p)
        /// </summary>
        Secp256r1,

        //Sect283k1,

        /// <summary>
        /// 283-bit curve over F(2m)
        /// </summary>
        Sect283r1,

        /// <summary>
        /// 384-bit curve over F(p)
        /// </summary>
        Secp384r1,


        //Sect409k1,

        /// <summary>
        /// 409-bit curve over F(2m)
        /// </summary>
        Sect409r1,

        /// <summary>
        /// 521-bit curve over F(p)
        /// </summary>
        Secp521r1,

        //Sect571k1,

        /// <summary>
        /// 571-bit curve over F(2m)
        /// </summary>
        Sect571r1
    }
}