#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using ProtoBuf;

namespace Obscur.Core.DTO
{
    /// <summary>
    ///     Schemes/standards for generating and verifying digital signatures.
    /// </summary>
    [ProtoContract]
    public enum SignatureScheme
    {
        None = 0,

        /// <summary>
        ///     Digital Signature Algorithm (DSA).
        /// </summary>
        [Obsolete] Dsa,

        /// <summary>
        ///     Elliptic Curve Digital Signature Algorithm (ECDSA).
        ///     Like DSA but using elliptic curves in place of large primes.
        /// </summary>
        ECDsa,

        /// <summary>
        ///     A relative of ECDSA with some additional desirable security properties over ECDSA.
        ///     Associated by virtue of its use with this scheme is the Edwards-type elliptic curve of the same name, "Ed25519".
        ///     Ed25519 should not and does not use any other curves, which is by design.
        /// </summary>
        /// <remarks>
        ///     Somewhat of a subset of <see cref="ECDsa" />, as they have far more in common than they are apart.
        ///     Nevertheless, Ed25519 is not strictly interoperable with ECDSA, despite being a close relative to it.
        ///     If the Ed25519 elliptic curve is used within ECDSA, it is used only as that - a curve.
        /// </remarks>
        /// <seealso cref="ECDsa" />
        Ed25519
    }
}
