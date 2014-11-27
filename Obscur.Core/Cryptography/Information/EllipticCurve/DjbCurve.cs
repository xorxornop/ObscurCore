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

namespace Obscur.Core.Cryptography.Information.EllipticCurve
{
    /// <summary>
    ///     Named elliptic curves from Daniel. J. Bernstein.
    /// </summary>
    public enum DjbCurve
    {
        /// <summary>
        ///     Can only be used for key agreements/exchanges. Cannot be used for signatures.
        /// </summary>
        /// <remarks>For signature capabilities, use <see cref="Ed25519" />.</remarks>
        Curve25519,

        /// <summary>
        ///     Can be used for key agreements/exchanges and signatures.
        ///     Uses the <see cref="Curve25519" /> curve in a different representation.
        /// </summary>
        /// <remarks>A Ed25519 key can be converted to and/or used as a <see cref="Curve25519" /> key.</remarks>
        Ed25519
    }
}
