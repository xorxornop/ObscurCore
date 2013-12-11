using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ObscurCore
{
    /// <summary>
    /// Public & private Curve25519 key pair 
    /// </summary>
    public class Curve25519Keypair
    {
        private byte[] _public;

        /// <summary>
        /// Public key of keypair. 
        /// Key can be distributed to non-user entities to enable communication.
        /// </summary>
        public byte[] Public {
            get {
                var retVal = new byte[_public.Length];
                Buffer.BlockCopy(_public, 0, retVal, 0, _public.Length);
                return retVal;
            }
            set {
                if (value.Length != 32) {
                    throw new ArgumentException("Not 32 bytes; Curve25519 keys are always 32 bytes (256 bits).");
                }
                _public = value;
            }
        }

        private byte[] _private;

        /// <summary>
        /// Private key of keypair. 
        /// Must not leak outside non-user-controlled system.
        /// </summary>
        public byte[] Private {
            get {
                var retVal = new byte[_private.Length];
                Buffer.BlockCopy(_private, 0, retVal, 0, _private.Length);
                return retVal;
            }
            set { _private = value; }
        }
    }
}
