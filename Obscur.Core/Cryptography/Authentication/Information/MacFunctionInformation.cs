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

using Obscur.Core.Cryptography.Ciphers.Block;

namespace Obscur.Core.Cryptography.Authentication.Information
{
    public class MacFunctionInformation : IPrimitiveInformation
    {
        /// <summary>
        ///     Size of the MAC produced in bits. Null if output size depends on configuration.
        /// </summary>
        public int? OutputSize { get; internal set; }

        /// <summary>
        ///     Name of the MAC function (must be a member of <see cref="MacFunction" />).
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        ///     Name to show a user or for a detailed specification.
        /// </summary>
        public string DisplayName { get; internal set; }
    }

    public sealed class CmacInformation : MacFunctionInformation
    {
//        public int GetMaximumOutputSize(BlockCipher cipher)
//        {
//            
//        }

        private static readonly int[] BlockSizes = { 64, 128 };

        public bool CanUseCipher(BlockCipher cipher)
        {
            return Athena.Cryptography.BlockCiphers[cipher].AllowableBlockSizesBits.NumberIsOneOf(BlockSizes);
        }
    }
}
