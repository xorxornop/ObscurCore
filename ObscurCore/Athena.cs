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
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Information;

namespace ObscurCore
{
    /// <summary>
    /// Athena provides knowledge of how all core functions must be configured for proper operation, 
    /// and provides end-user-display-friendly names.
    /// </summary>
    public static class Athena
    {
        public static class Cryptography
        {
            static Cryptography()
            {
                BlockCipherDictionary = new Dictionary<BlockCipher, SymmetricCipherDescription> {
                    {
                        BlockCipher.Aes, new SymmetricCipherDescription {
                            Name = BlockCipher.Aes.ToString(),
                            DisplayName = "Advanced Encryption Standard (AES)",
                            AllowableBlockSizes = new[] { 128 },
                            DefaultBlockSize = 128,
                            AllowableKeySizes = new[] { 128, 192, 256 },
                            DefaultKeySize = 256
                        }
                    }, {
                        BlockCipher.Blowfish, new SymmetricCipherDescription {
                            Name = BlockCipher.Blowfish.ToString(),
                            DisplayName = "Blowfish",
                            AllowableBlockSizes = new[] { 64 },
                            DefaultBlockSize = 64,
                            AllowableKeySizes =
                                new[] { 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
                            DefaultKeySize = 256
                        }
                    }, {
                        BlockCipher.Camellia, new SymmetricCipherDescription {
                            Name = BlockCipher.Camellia.ToString(),
                            DisplayName = "Camellia",
                            AllowableBlockSizes = new[] { 128 },
                            DefaultBlockSize = 128,
                            AllowableKeySizes = new[] { 128, 192, 256 },
                            DefaultKeySize = 256
                        }
                    },
#if INCLUDE_CAST5AND6
                    {
                        BlockCipher.Cast5, new SymmetricCipherDescription {
                            Name = BlockCipher.Cast5.ToString(),
                            DisplayName = "CAST-5 (CAST-128)",
                            AllowableBlockSizes = new[] { 64 },
                            DefaultBlockSize = 64,
                            AllowableKeySizes = new[] { 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128 },
                            DefaultKeySize = 128
                        }
                    },
                    {
                        BlockCipher.Cast6, new SymmetricCipherDescription {
                            Name = BlockCipher.Cast6.ToString(),
                            DisplayName = "CAST-6 (CAST-256)",
                            AllowableBlockSizes = new[] { 128 },
                            DefaultBlockSize = 128,
                            AllowableKeySizes = new[] { 128, 160, 192, 224, 256 },
                            DefaultKeySize = 256
                        }
                    },
#endif
#if INCLUDE_IDEA
                    {
                        BlockCipher.Idea, new SymmetricCipherDescription {
                            Name = BlockCipher.Idea.ToString(),
                            DisplayName = "International Data Encryption Algorithm (IDEA)",
                            AllowableBlockSizes = new[] { 64 },
                            DefaultBlockSize = 64,
                            AllowableKeySizes = new[] { 128 },
                            DefaultKeySize = 128
                        }
                    },
#endif
                    {
                        BlockCipher.Noekeon, new SymmetricCipherDescription {
                            Name = BlockCipher.Noekeon.ToString(),
                            DisplayName = "NOEKEON",
                            AllowableBlockSizes = new[] { 128 },
                            DefaultBlockSize = 128,
                            AllowableKeySizes = new[] { 128 },
                            DefaultKeySize = 128
                        }
                    }, {
                        BlockCipher.Rc6, new SymmetricCipherDescription {
                            Name = BlockCipher.Rc6.ToString(),
                            DisplayName = "RC6",
                            AllowableBlockSizes = new[] { 128 },
                            DefaultBlockSize = 128,
                            AllowableKeySizes = new[] { 128, 192, 256 },
                            DefaultKeySize = 256
                        }
                    }, {
                        BlockCipher.Serpent, new SymmetricCipherDescription {
                            Name = BlockCipher.Serpent.ToString(),
                            DisplayName = "Serpent",
                            AllowableBlockSizes = new[] { 128 },
                            DefaultBlockSize = 128,
                            AllowableKeySizes = new[] { 128, 192, 256 },
                            DefaultKeySize = 256
                        }
                    }, {
                        BlockCipher.Threefish, new SymmetricCipherDescription {
                            Name = BlockCipher.Threefish.ToString(),
                            DisplayName = "Threefish",
                            AllowableBlockSizes = new[] { 256, 512, 1024 },
                            DefaultBlockSize = 256,
                            AllowableKeySizes = new[] { 256, 512, 1024 },
                            DefaultKeySize = 256
                        }
                    }, {
                        BlockCipher.Twofish, new SymmetricCipherDescription {
                            Name = BlockCipher.Twofish.ToString(),
                            DisplayName = "Twofish",
                            AllowableBlockSizes = new[] { 128 },
                            DefaultBlockSize = 128,
                            AllowableKeySizes = new[] { 128, 192, 256 },
                            DefaultKeySize = 256
                        }
                    }
                };

                StreamCipherDictionary = new Dictionary<StreamCipher, SymmetricCipherDescription> {
                    {
                        StreamCipher.Hc128, new SymmetricCipherDescription {
                            Name = StreamCipher.Hc128.ToString(),
                            DisplayName = "HC-128",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = new[] { 128 },
                            DefaultIvSize = 128,
                            AllowableKeySizes = new[] { 128 },
                            DefaultKeySize = 128
                        }
                    }, {
                        StreamCipher.Hc256, new SymmetricCipherDescription {
                            Name = StreamCipher.Hc256.ToString(),
                            DisplayName = "HC-256",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = new[] { 128, 256 },
                            DefaultIvSize = 256,
                            AllowableKeySizes = new[] { 128, 256 },
                            DefaultKeySize = 256
                        }
                    }, {
                        StreamCipher.Rabbit, new SymmetricCipherDescription {
                            Name = StreamCipher.Rabbit.ToString(),
                            DisplayName = "Rabbit",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = new[] { 64 },
                            DefaultIvSize = 64,
                            AllowableKeySizes = new[] { 128 },
                            DefaultKeySize = 128
                        }
                    },
#if(INCLUDE_RC4)
                    {
                        StreamCipher.Rc4, new SymmetricCipherDescription {
                            Name = StreamCipher.Rc4.ToString(),
                            DisplayName = "RC4",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = null,
                            DefaultIvSize = -1,
                            AllowableKeySizes = new[] { 40, 56, 64, 72, 96, 128, 192, 256 },
                            DefaultKeySize = 128
                        }
                    },
#endif
                    {
                        StreamCipher.Salsa20, new SymmetricCipherDescription {
                            Name = StreamCipher.Salsa20.ToString(),
                            DisplayName = "Salsa20",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = new[] { 64 },
                            DefaultIvSize = 64,
                            AllowableKeySizes = new[] { 128, 256 },
                            DefaultKeySize = 256
                        }
                    }, {
                        StreamCipher.ChaCha, new SymmetricCipherDescription {
                            Name = StreamCipher.ChaCha.ToString(),
                            DisplayName = "ChaCha",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = new[] { 64 },
                            DefaultIvSize = 64,
                            AllowableKeySizes = new[] { 128, 256 },
                            DefaultKeySize = 256
                        }
                    }, {
                        StreamCipher.XSalsa20, new SymmetricCipherDescription {
                            Name = StreamCipher.XSalsa20.ToString(),
                            DisplayName = "XSalsa20",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = new[] { 64, 128, 192 },
                            DefaultIvSize = 192,
                            AllowableKeySizes = new[] { 80, 128, 256 },
                            DefaultKeySize = 256
                        }
                    }, {
                        StreamCipher.Sosemanuk, new SymmetricCipherDescription {
                            Name = StreamCipher.Sosemanuk.ToString(),
                            DisplayName = "SOSEMANUK",
                            AllowableBlockSizes = null,
                            DefaultBlockSize = -1,
                            AllowableIvSizes = new[] { 32, 48, 64, 80, 96, 112, 128 },
                            DefaultIvSize = 128,
                            AllowableKeySizes = new[] { 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256 },
                            DefaultKeySize = 128
                        }
                    }
                };

                BlockCipherModeDictionary = new Dictionary<BlockCipherMode, SymmetricCipherModeDescription> {
                    {
                        BlockCipherMode.Cbc, new SymmetricCipherModeDescription {
                            Name = BlockCipherMode.Cbc.ToString(),
                            DisplayName = "Ciphertext Block Chaining (CBC)",
                            PaddingRequirement = PaddingRequirement.Always,
                            AllowableBlockSizes = new[] { -1 },
                            NonceReusePolicy = NoncePolicy.RequireRandom
                        }
                    }, {
                        BlockCipherMode.Cfb, new SymmetricCipherModeDescription {
                            Name = BlockCipherMode.Cfb.ToString(),
                            DisplayName = "Cipher Feedback (CFB)",
                            PaddingRequirement = PaddingRequirement.None,
                            AllowableBlockSizes = new[] { -1 },
                            NonceReusePolicy = NoncePolicy.CounterAllowed
                        }
                    }, {
                        BlockCipherMode.Ctr, new SymmetricCipherModeDescription {
                            Name = BlockCipherMode.Ctr.ToString(),
                            DisplayName = "Counter / Segmented Integer Counter (CTR/SIC)",
                            PaddingRequirement = PaddingRequirement.None,
                            AllowableBlockSizes = new[] { -1 },
                            NonceReusePolicy = NoncePolicy.CounterAllowed
                        }
                    }, {
                        BlockCipherMode.Ofb, new SymmetricCipherModeDescription {
                            Name = BlockCipherMode.Ofb.ToString(),
                            DisplayName = "Output Feedback (OFB)",
                            PaddingRequirement = PaddingRequirement.None,
                            AllowableBlockSizes = new[] { -1 },
                            NonceReusePolicy = NoncePolicy.CounterAllowed
                        }
                    }
                };

                BlockCipherPaddingDictionary = new Dictionary<BlockCipherPadding, SymmetricCipherPaddingDescription> {
                    {
                        BlockCipherPadding.Iso10126D2, new SymmetricCipherPaddingDescription {
                            Name = BlockCipherPadding.Iso10126D2.ToString(),
                            DisplayName = "ISO 10126-2"
                        }
                    }, {
                        BlockCipherPadding.Iso7816D4, new SymmetricCipherPaddingDescription {
                            Name = BlockCipherPadding.Iso7816D4.ToString(),
                            DisplayName = "ISO/IEC 7816-4"
                        }
                    }, {
                        BlockCipherPadding.Pkcs7, new SymmetricCipherPaddingDescription {
                            Name = BlockCipherPadding.Pkcs7.ToString(),
                            DisplayName = "PKCS 7"
                        }
                    }, {
                        BlockCipherPadding.Tbc, new SymmetricCipherPaddingDescription {
                            Name = BlockCipherPadding.Tbc.ToString(),
                            DisplayName = "Trailing Bit Complement (TBC)"
                        }
                    }, {
                        BlockCipherPadding.X923, new SymmetricCipherPaddingDescription {
                            Name = BlockCipherPadding.X923.ToString(),
                            DisplayName = "ANSI X.923"
                        }
                    }
                };

                HashFunctionDictionary = new Dictionary<HashFunction, HashFunctionDescription> {
                    {
                        HashFunction.Blake2B256, new HashFunctionDescription {
                            Name = HashFunction.Blake2B256.ToString(),
                            DisplayName = "BLAKE-2B-256",
                            OutputSize = 256
                        }
                    }, {
                        HashFunction.Blake2B384, new HashFunctionDescription {
                            Name = HashFunction.Blake2B384.ToString(),
                            DisplayName = "BLAKE-2B-384",
                            OutputSize = 384
                        }
                    }, {
                        HashFunction.Blake2B512, new HashFunctionDescription {
                            Name = HashFunction.Blake2B512.ToString(),
                            DisplayName = "BLAKE-2B-512",
                            OutputSize = 512
                        }
                    }, {
                        HashFunction.Keccak224, new HashFunctionDescription {
                            Name = HashFunction.Keccak224.ToString(),
                            DisplayName = "Keccak-224 (SHA-3-224)",
                            OutputSize = 224
                        }
                    }, {
                        HashFunction.Keccak256, new HashFunctionDescription {
                            Name = HashFunction.Keccak256.ToString(),
                            DisplayName = "Keccak-256 (SHA-3-256)",
                            OutputSize = 256
                        }
                    }, {
                        HashFunction.Keccak384, new HashFunctionDescription {
                            Name = HashFunction.Keccak384.ToString(),
                            DisplayName = "Keccak-384 (SHA-3-384)",
                            OutputSize = 384
                        }
                    }, {
                        HashFunction.Keccak512, new HashFunctionDescription {
                            Name = HashFunction.Keccak512.ToString(),
                            DisplayName = "Keccak-512 (SHA-3-512)",
                            OutputSize = 512
                        }
                    }, {
                        HashFunction.Ripemd160, new HashFunctionDescription {
                            Name = HashFunction.Ripemd160.ToString(),
                            DisplayName = "RIPEMD-160",
                            OutputSize = 160
                        }
                    },
#if INCLUDE_SHA1
                    {
                        HashFunction.Sha1, new HashFunctionDescription {
                            Name = HashFunction.Sha1.ToString(),
                            DisplayName = "SHA-1",
                            OutputSize = 160
                        }
                    },
#endif
                    {
                        HashFunction.Sha256, new HashFunctionDescription {
                            Name = HashFunction.Sha256.ToString(),
                            DisplayName = "SHA-2-256",
                            OutputSize = 256
                        }
                    }, {
                        HashFunction.Sha512, new HashFunctionDescription {
                            Name = HashFunction.Sha512.ToString(),
                            DisplayName = "SHA-2-512",
                            OutputSize = 512
                        }
                    }, {
                        HashFunction.Tiger, new HashFunctionDescription {
                            Name = HashFunction.Tiger.ToString(),
                            DisplayName = "Tiger",
                            OutputSize = 192
                        }
                    }
                };

                MacFunctionDictionary = new Dictionary<MacFunction, MacFunctionDescription> {
                    {
                        MacFunction.Blake2B256, new MacFunctionDescription {
                            Name = MacFunction.Blake2B256.ToString(),
                            DisplayName = "BLAKE-2B-256",
                            OutputSize = 256,
                        }
                    }, {
                        MacFunction.Blake2B384, new MacFunctionDescription {
                            Name = MacFunction.Blake2B384.ToString(),
                            DisplayName = "BLAKE-2B-384",
                            OutputSize = 384,
                        }
                    }, {
                        MacFunction.Blake2B512, new MacFunctionDescription {
                            Name = MacFunction.Blake2B512.ToString(),
                            DisplayName = "BLAKE-2B-512",
                            OutputSize = 512
                        }
                    }, {
                        MacFunction.Keccak224, new MacFunctionDescription {
                            Name = MacFunction.Keccak224.ToString(),
                            DisplayName = "Keccak-224 (SHA-3-224)",
                            OutputSize = 224
                        }
                    }, {
                        MacFunction.Keccak256, new MacFunctionDescription {
                            Name = MacFunction.Keccak256.ToString(),
                            DisplayName = "Keccak-256 (SHA-3-256)",
                            OutputSize = 256
                        }
                    }, {
                        MacFunction.Keccak384, new MacFunctionDescription {
                            Name = MacFunction.Keccak384.ToString(),
                            DisplayName = "Keccak-384 (SHA-3-384)",
                            OutputSize = 384
                        }
                    }, {
                        MacFunction.Keccak512, new MacFunctionDescription {
                            Name = MacFunction.Keccak512.ToString(),
                            DisplayName = "Keccak-512 (SHA-3-512)",
                            OutputSize = 512
                        }
                    }, {
                        MacFunction.Poly1305, new MacFunctionDescription {
                            Name = MacFunction.Poly1305.ToString(),
                            DisplayName = "Poly1305",
                            OutputSize = 128
                        }
                    }, {
                        MacFunction.Cmac, new MacFunctionDescription {
                            Name = MacFunction.Cmac.ToString(),
                            DisplayName = "CMAC/OMAC1 construction",
                            OutputSize = null
                        }
                    }, {
                        MacFunction.Hmac, new MacFunctionDescription {
                            Name = MacFunction.Hmac.ToString(),
                            DisplayName = "HMAC construction",
                            OutputSize = null
                        }
                    }
                };

                KdfDictionary = new Dictionary<KeyDerivationFunction, KdfDescription> {
                    {
                        KeyDerivationFunction.Pbkdf2, new KdfDescription {
                            Name = KeyDerivationFunction.Pbkdf2.ToString(),
                            DisplayName = "Password-Based Key Derivation Function 2 (PBKDF2)"
                        }
                    }, {
                        KeyDerivationFunction.Scrypt, new KdfDescription {
                            Name = KeyDerivationFunction.Scrypt.ToString(),
                            DisplayName = "Scrypt"
                        }
                    }
                };

                CsprngDictionary = new Dictionary<CsPseudorandomNumberGenerator, CsprngDescription> {
                    {
                        CsPseudorandomNumberGenerator.Salsa20, new CsprngDescription {
                            Name = CsPseudorandomNumberGenerator.Salsa20.ToString(),
                            DisplayName = "Salsa20 keystream CSPRNG"
                        }
                    }, {
                        CsPseudorandomNumberGenerator.Sosemanuk, new CsprngDescription {
                            Name = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
                            DisplayName = "SOSEMANUK keystream CSPRNG"
                        }
                    }, {
                        CsPseudorandomNumberGenerator.Rabbit, new CsprngDescription {
                            Name = CsPseudorandomNumberGenerator.Rabbit.ToString(),
                            DisplayName = "Rabbit keystream CSPRNG"
                        }
                    }
                };
            }

            // Data storage.
            private static readonly Dictionary<BlockCipher, SymmetricCipherDescription> BlockCipherDictionary;
            private static readonly Dictionary<StreamCipher, SymmetricCipherDescription> StreamCipherDictionary;

            private static readonly Dictionary<BlockCipherMode, SymmetricCipherModeDescription>
                BlockCipherModeDictionary;

            private static readonly Dictionary<BlockCipherPadding, SymmetricCipherPaddingDescription>
                BlockCipherPaddingDictionary;

            private static readonly Dictionary<HashFunction, HashFunctionDescription> HashFunctionDictionary;
            private static readonly Dictionary<MacFunction, MacFunctionDescription> MacFunctionDictionary;
            private static readonly Dictionary<KeyDerivationFunction, KdfDescription> KdfDictionary;
            private static readonly Dictionary<CsPseudorandomNumberGenerator, CsprngDescription> CsprngDictionary;

            // Exposure methods

            public static IReadOnlyDictionary<BlockCipher, SymmetricCipherDescription> BlockCiphers
            {
                get { return BlockCipherDictionary; }
            }

            public static IReadOnlyDictionary<StreamCipher, SymmetricCipherDescription> StreamCiphers
            {
                get { return StreamCipherDictionary; }
            }

            public static IReadOnlyDictionary<BlockCipherMode, SymmetricCipherModeDescription> BlockCipherModes
            {
                get { return BlockCipherModeDictionary; }
            }

            public static IReadOnlyDictionary<BlockCipherPadding, SymmetricCipherPaddingDescription> BlockCipherPaddings
            {
                get { return BlockCipherPaddingDictionary; }
            }

            public static IReadOnlyDictionary<HashFunction, HashFunctionDescription> HashFunctions
            {
                get { return HashFunctionDictionary; }
            }

            public static IReadOnlyDictionary<MacFunction, MacFunctionDescription> MacFunctions
            {
                get { return MacFunctionDictionary; }
            }

            public static IReadOnlyDictionary<KeyDerivationFunction, KdfDescription> KeyDerivationFunctions
            {
                get { return KdfDictionary; }
            }

            public static IReadOnlyDictionary<CsPseudorandomNumberGenerator, CsprngDescription> Csprngs
            {
                get { return CsprngDictionary; }
            }
        }

        public static class Packaging
        {
            /// <summary>
            /// Version of operational scheme and DTO objects that code includes support for
            /// </summary>
            public const int HeaderVersion = 1;

            public const char PathDirectorySeperator = '/';
            public static string PathRelativeUp = ".." + PathDirectorySeperator;

            public static byte[] GetHeaderTag()
            {
                return Encoding.UTF8.GetBytes("OCpkg-OHAI");
            }

            public static byte[] GetTrailerTag()
            {
                return Encoding.UTF8.GetBytes("KBAI-OCpkg");
            }
        }
    }
}
