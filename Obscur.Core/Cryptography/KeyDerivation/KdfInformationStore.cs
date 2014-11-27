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
using Obscur.Core.Cryptography.KeyDerivation.Information;

namespace Obscur.Core.Cryptography.KeyDerivation
{
    internal static class KdfInformationStore
    {
        internal static readonly ImmutableDictionary<KeyDerivationFunction, KdfInformation> KdfDictionary;

        static KdfInformationStore()
        {
            KdfDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<KeyDerivationFunction, KdfInformation>(
                    KeyDerivationFunction.Pbkdf2, new KdfInformation {
                        Name = KeyDerivationFunction.Pbkdf2.ToString(),
                        DisplayName = "Password-Based Key Derivation Function 2 (PBKDF2)"
                    }),
                new KeyValuePair<KeyDerivationFunction, KdfInformation>(
                    KeyDerivationFunction.Scrypt, new KdfInformation {
                        Name = KeyDerivationFunction.Scrypt.ToString(),
                        DisplayName = "Scrypt"
                    })
            });
        }
    }
}
