using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace ObscurCore.Cryptography
{
    /// <summary>
    ///     Base class for exceptions originating in and concerning cryptographic systems and/or primitives. 
    ///     Displaying or transmitting information originating in these exceptions should be done only with care, 
    ///     as sensitive internal state may thereby be leaked, and a weakening or breaking of security properties may result.
    /// </summary>
    /// <remarks>
    ///     See: padding oracles, for a good demonstration as to why it is important to not provide cryptographic exception detail to 3rd parties.
    /// </remarks>
    public class CryptographicException : Exception
    {
        private const string ExceptionMessage =
            "Unspecified cryptographic error; it may have been redacted for security.";

        public CryptographicException() { }
        public CryptographicException(string message) : base(message ?? ExceptionMessage) { }
        public CryptographicException(string message, Exception inner) : base(message ?? ExceptionMessage, inner) { }
    }
}
