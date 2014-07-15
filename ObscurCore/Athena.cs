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
using System.Collections.Immutable;
using System.Text;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Authentication.Information;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Information;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Entropy.Information;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Information;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.KeyDerivation.Information;

namespace ObscurCore
{
    /// <summary>
    ///     Athena provides knowledge of how all core functions must be configured for proper operation,
    ///     and provides end-user-display-friendly names.
    /// </summary>
    public static class Athena
    {
        public static class Cryptography
        {
            public static IReadOnlyDictionary<BlockCipher, BlockCipherInformation> BlockCiphers
            {
                get { return CipherInformationStore.BlockCipherDictionary; }
            }

            public static IReadOnlyDictionary<StreamCipher, StreamCipherInformation> StreamCiphers
            {
                get { return CipherInformationStore.StreamCipherDictionary; }
            }

            public static IReadOnlyDictionary<BlockCipherMode, BlockCipherModeInformation> BlockCipherModes
            {
                get { return CipherInformationStore.BlockCipherModeDictionary; }
            }

            public static IReadOnlyDictionary<BlockCipherPadding, BlockCipherPaddingInformation> BlockCipherPaddings
            {
                get { return CipherInformationStore.BlockCipherPaddingDictionary; }
            }

            public static IReadOnlyDictionary<HashFunction, HashFunctionInformation> HashFunctions
            {
                get { return AuthenticationInformationStore.HashFunctionDictionary; }
            }

            public static IReadOnlyDictionary<MacFunction, MacFunctionInformation> MacFunctions
            {
                get { return AuthenticationInformationStore.MacFunctionDictionary; }
            }

            public static IReadOnlyDictionary<string, EllipticCurveInformation> Curves
            {
                get { return EllipticCurveInformationStore.CurveDictionary; }
            }

            public static IReadOnlyDictionary<KeyDerivationFunction, KdfInformation> KeyDerivationFunctions
            {
                get { return KdfInformationStore.KdfDictionary; }
            }

            public static IReadOnlyDictionary<CsPseudorandomNumberGenerator, CsprngDescription> Csprngs
            {
                get { return CsprngInformationStore.CsprngDictionary; }
            }
        }

        public static class Packaging
        {
            /// <summary>
            ///     Version of operational scheme and DTO objects that code includes support for
            /// </summary>
            public const int PackageFormatVersion = 1;

            public const char PathDirectorySeperator = '/';
            public static readonly string PathRelativeUp = "..";
            public static readonly string PathRelativeUpSeperator = PathRelativeUp + PathDirectorySeperator;

            public static byte[] GetPackageHeaderTag()
            {
                return Encoding.UTF8.GetBytes("OCpkgV1>"); // 8 bytes
            }

            public static byte[] GetPackageTrailerTag()
            {
                return Encoding.UTF8.GetBytes("<|OCpkg|"); // 8 bytes
            }
        }
    }
}
