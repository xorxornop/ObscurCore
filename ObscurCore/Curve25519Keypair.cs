//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using System;

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
				Array.Copy(_public, 0, retVal, 0, _public.Length);
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
				Array.Copy(_private, 0, retVal, 0, _private.Length);
                return retVal;
            }
            set { _private = value; }
        }
    }
}
