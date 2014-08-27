#region License

// 	Copyright 2014-2014 Matthew Ducker
// 	
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	
// 	You may obtain a copy of the License at
// 		
// 		http://www.apache.org/licenses/LICENSE-2.0
// 	
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and 
// 	limitations under the License.

#endregion

using ObscurCore.Cryptography.Support.Math;

namespace ObscurCore.Cryptography.Signing
{
    /// <summary>
    ///     Interface for implementations of the Digital Signature Algorithm (DSA).
    /// </summary>
    public interface IDsa
    {
        /// <summary>
        ///     Whether signing is possible with the key(s) currently loaded.
        /// </summary>
        bool SigningCapable { get; }

        /// <summary>
        ///     Whether verification of signatures is possible with the key(s) currently loaded.
        /// </summary>
        bool VerificationCapable { get; }

        /// <summary>
        ///     Name of the DSA-family algorithm implemented.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        ///     Sign the passed in message (often the output of a hash/digest function).
        /// </summary>
        /// <remarks>
        ///     5.3 pg. 28. 
        ///     For conventional DSA, <paramref name="message"/> is SHA1 hash 
        ///     of actual message, but this is now obselete.
        /// </remarks>
        /// <param name="message">Data/message to be signed.</param>
        /// <param name="r"></param>
        /// <param name="s"></param>
        void GenerateSignature(byte[] message, out BigInteger r, out BigInteger s);

        /// <summary>
        ///     Verify given <paramref name="message" /> against the signature
        ///     values <paramref name="r" /> and <paramref name="s" />.
        /// </summary>
        /// <remarks>
        ///     5.4 pg. 29.
        ///     For conventional DSA, <paramref name="message"/> is SHA1 hash 
        ///     of actual message, but this is now obselete.
        /// </remarks>
        /// <param name="message">Data/message to be verified.</param>
        /// <param name="r"></param>
        /// <param name="s"></param>
        /// <returns>
        ///     <c>true</c> if the values <paramref name="r"/> and <paramref name="s"/> 
        ///     represent a valid DSA signature for <paramref name="message"/> (message 
        ///     likely authentic). Otherwise, <c>false</c> (message may be forged).
        /// </returns>
        bool VerifySignature(byte[] message, BigInteger r, BigInteger s);
    }
}
