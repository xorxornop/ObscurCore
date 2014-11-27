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

using System.Collections.Generic;
using System.Text;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.Authentication.Information;
using Obscur.Core.Cryptography.Ciphers;
using Obscur.Core.Cryptography.Ciphers.Block;
using Obscur.Core.Cryptography.Ciphers.Information;
using Obscur.Core.Cryptography.Ciphers.Stream;
using Obscur.Core.Cryptography.Entropy;
using Obscur.Core.Cryptography.Entropy.Information;
using Obscur.Core.Cryptography.Information;
using Obscur.Core.Cryptography.Information.EllipticCurve;
using Obscur.Core.Cryptography.KeyDerivation;
using Obscur.Core.Cryptography.KeyDerivation.Information;

namespace Obscur.Core
{
    /// <summary>
    ///     Athena provides knowledge of how all core functions must be configured for proper operation,
    ///     and provides end-user-display-friendly names.
    /// </summary>
    public static class Athena
    {
        /// <summary>
        ///     Cryptographic primitive information provider.
        /// </summary>
        public static class Cryptography
        {
            /// <summary>
            ///     Information about block cipher primitives.
            /// </summary>
            public static IReadOnlyDictionary<BlockCipher, BlockCipherInformation> BlockCiphers
            {
                get { return CipherInformationStore.BlockCipherDictionary; }
            }

            /// <summary>
            ///     Information about stream cipher primitives.
            /// </summary>
            public static IReadOnlyDictionary<StreamCipher, StreamCipherInformation> StreamCiphers
            {
                get { return CipherInformationStore.StreamCipherDictionary; }
            }

            /// <summary>
            ///     Information about block cipher modes of operation.
            /// </summary>
            public static IReadOnlyDictionary<BlockCipherMode, BlockCipherModeInformation> BlockCipherModes
            {
                get { return CipherInformationStore.BlockCipherModeDictionary; }
            }

            /// <summary>
            ///     Information about block cipher padding schemes.
            /// </summary>
            public static IReadOnlyDictionary<BlockCipherPadding, BlockCipherPaddingInformation> BlockCipherPaddings
            {
                get { return CipherInformationStore.BlockCipherPaddingDictionary; }
            }

            /// <summary>
            ///     Information about hash/digest authentication primitives.
            /// </summary>
            public static IReadOnlyDictionary<HashFunction, HashFunctionInformation> HashFunctions
            {
                get { return AuthenticationInformationStore.HashFunctionDictionary; }
            }

            /// <summary>
            ///     Information about MAC authentication primitives.
            /// </summary>
            public static IReadOnlyDictionary<MacFunction, MacFunctionInformation> MacFunctions
            {
                get { return AuthenticationInformationStore.MacFunctionDictionary; }
            }

            /// <summary>
            ///     Information about named elliptic curves.
            /// </summary>
            public static IReadOnlyDictionary<string, EcCurveInformation> EllipticCurves
            {
                get { return EcInformationStore.CurveDictionary; }
            }

            /// <summary>
            ///     Information about key derivation functions.
            /// </summary>
            public static IReadOnlyDictionary<KeyDerivationFunction, KdfInformation> KeyDerivationFunctions
            {
                get { return KdfInformationStore.KdfDictionary; }
            }

            /// <summary>
            /// Information about CSPRNG primitives.
            /// </summary>
            public static IReadOnlyDictionary<CsPseudorandomNumberGenerator, CsprngDescription> Csprngs
            {
                get { return CsprngInformationStore.CsprngDictionary; }
            }
        }

        /// <summary>
        ///     Packaging system information provider.
        /// </summary>
        public static class Packaging
        {
            /// <summary>
            ///     Version of package schema (and so, DTO objects) 
            ///     that code includes support for.
            /// </summary>
            public const int PackageFormatVersion = 1;

            /// <summary>
            ///     Character that denotes a forward traversal (deeper) step in the 
            ///     path tree from the current position in the package filesystem schema.
            /// </summary>
            public const char PathDirectorySeperator = '/';

            /// <summary>
            ///     Character sequence that can prefix a <see cref="PathDirectorySeperator"/> to reverse 
            ///     the direction of tree traversal from the current position in the package filesystem schema.
            /// </summary>
            public static readonly string PathRelativeUp = "..";

            /// <summary>
            ///     Character sequence that denotes a reverse traversal (shallower) step in the 
            ///     path tree from the current position in the package filesystem schema.
            /// </summary>
            public static readonly string PathRelativeUpSeperator = PathRelativeUp + PathDirectorySeperator;

            /// <summary>
            ///     Get the header byte sequence used to denote the start of an ObscurCore package.
            /// </summary>
            /// <returns>Header tag as byte array.</returns>
            public static byte[] GetPackageHeaderTag()
            {
                return Encoding.UTF8.GetBytes("OCpkgV1>"); // 8 bytes
            }

            /// <summary>
            ///     Get the trailer byte sequence used to denote the end of an ObscurCore package.
            /// </summary>
            /// <returns>Trailer tag as byte array.</returns>
            public static byte[] GetPackageTrailerTag()
            {
                return Encoding.UTF8.GetBytes("<|OCpkg|"); // 8 bytes
            }
        }
    }
}
