using System;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Cryptography.Information.EllipticCurve
{
    class DjbEcInformation : EcCurveInformation
    {
        /// <summary>
        ///     Get parameter object for performing computations.
        /// </summary>
        /// <returns></returns>
        public override ECDomainParameters GetParameters()
        {
            throw new NotSupportedException("These curves are implemented in a non-compatible way.");
        }
    }
}
