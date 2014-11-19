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
using ObscurCore.Cryptography.Authentication.Information;

namespace ObscurCore.Cryptography.Authentication
{
    internal static class AuthenticationInformationStore
    {
        internal static readonly ImmutableDictionary<HashFunction, HashFunctionInformation> HashFunctionDictionary;
        internal static readonly ImmutableDictionary<MacFunction, MacFunctionInformation> MacFunctionDictionary;

        static AuthenticationInformationStore()
        {
            HashFunctionDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Blake2B256, new HashFunctionInformation {
                        Name = HashFunction.Blake2B256.ToString(),
                        DisplayName = "BLAKE-2B-256",
                        OutputSizeBits = 256
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Blake2B384, new HashFunctionInformation {
                        Name = HashFunction.Blake2B384.ToString(),
                        DisplayName = "BLAKE-2B-384",
                        OutputSizeBits = 384
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Blake2B512, new HashFunctionInformation {
                        Name = HashFunction.Blake2B512.ToString(),
                        DisplayName = "BLAKE-2B-512",
                        OutputSizeBits = 512
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Keccak224, new HashFunctionInformation {
                        Name = HashFunction.Keccak224.ToString(),
                        DisplayName = "Keccak-224 (SHA-3-224)",
                        OutputSizeBits = 224
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Keccak256, new HashFunctionInformation {
                        Name = HashFunction.Keccak256.ToString(),
                        DisplayName = "Keccak-256 (SHA-3-256)",
                        OutputSizeBits = 256
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Keccak384, new HashFunctionInformation {
                        Name = HashFunction.Keccak384.ToString(),
                        DisplayName = "Keccak-384 (SHA-3-384)",
                        OutputSizeBits = 384
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Keccak512, new HashFunctionInformation {
                        Name = HashFunction.Keccak512.ToString(),
                        DisplayName = "Keccak-512 (SHA-3-512)",
                        OutputSizeBits = 512
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Ripemd160, new HashFunctionInformation {
                        Name = HashFunction.Ripemd160.ToString(),
                        DisplayName = "RIPEMD-160",
                        OutputSizeBits = 160
#if INCLUDE_SHA1
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Sha1, new HashFunctionInformation {
                        Name = HashFunction.Sha1.ToString(),
                        DisplayName = "SHA-1",
                        OutputSizeBits = 160
#endif
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Sha256, new HashFunctionInformation {
                        Name = HashFunction.Sha256.ToString(),
                        DisplayName = "SHA-2-256",
                        OutputSizeBits = 256
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Sha512, new HashFunctionInformation {
                        Name = HashFunction.Sha512.ToString(),
                        DisplayName = "SHA-2-512",
                        OutputSizeBits = 512
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                    HashFunction.Tiger, new HashFunctionInformation {
                        Name = HashFunction.Tiger.ToString(),
                        DisplayName = "Tiger",
                        OutputSizeBits = 192
                    }),
                new KeyValuePair<HashFunction, HashFunctionInformation>(
                HashFunction.Whirlpool, new HashFunctionInformation {
                    Name = HashFunction.Whirlpool.ToString(),
                    DisplayName = "Whirlpool",
                    OutputSizeBits = 512
                })
            });

            MacFunctionDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Blake2B256, new MacFunctionInformation {
                        Name = MacFunction.Blake2B256.ToString(),
                        DisplayName = "BLAKE-2B-256",
                        OutputSize = 256,
                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Blake2B384, new MacFunctionInformation {
                        Name = MacFunction.Blake2B384.ToString(),
                        DisplayName = "BLAKE-2B-384",
                        OutputSize = 384,
                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Blake2B512, new MacFunctionInformation {
                        Name = MacFunction.Blake2B512.ToString(),
                        DisplayName = "BLAKE-2B-512",
                        OutputSize = 512
                    }),
//                new KeyValuePair<MacFunction, MacFunctionInformation>(
//                    MacFunction.Keccak224, new MacFunctionInformation {
//                        Name = MacFunction.Keccak224.ToString(),
//                        DisplayName = "Keccak-224 (SHA-3-224)",
//                        OutputSize = 224
//                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Keccak256, new MacFunctionInformation {
                        Name = MacFunction.Keccak256.ToString(),
                        DisplayName = "Keccak-256 (SHA-3-256)",
                        OutputSize = 256
                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Keccak384, new MacFunctionInformation {
                        Name = MacFunction.Keccak384.ToString(),
                        DisplayName = "Keccak-384 (SHA-3-384)",
                        OutputSize = 384
                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Keccak512, new MacFunctionInformation {
                        Name = MacFunction.Keccak512.ToString(),
                        DisplayName = "Keccak-512 (SHA-3-512)",
                        OutputSize = 512
                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Poly1305, new MacFunctionInformation {
                        Name = MacFunction.Poly1305.ToString(),
                        DisplayName = "Poly1305",
                        OutputSize = 128
                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Cmac, new MacFunctionInformation {
                        Name = MacFunction.Cmac.ToString(),
                        DisplayName = "CMAC/OMAC1 construction",
                        OutputSize = null
                    }),
                new KeyValuePair<MacFunction, MacFunctionInformation>(
                    MacFunction.Hmac, new MacFunctionInformation {
                        Name = MacFunction.Hmac.ToString(),
                        DisplayName = "HMAC construction",
                        OutputSize = null
                    })
            });
        }
    }
}
