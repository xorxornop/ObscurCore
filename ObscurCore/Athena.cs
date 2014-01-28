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
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
//using ObscurCore.Cryptography.Ciphers;
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
            static Cryptography() {

                // Add symmetric block ciphers

                _blockCipherDirectory.Add(SymmetricBlockCipher.Aes, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Aes.ToString(),
                    DisplayName = "Advanced Encryption Standard (AES)",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                _blockCipherDirectory.Add(SymmetricBlockCipher.Blowfish, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Blowfish.ToString(),
                    DisplayName = "Blowfish",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
                    DefaultKeySize = 256
                });
                _blockCipherDirectory.Add(SymmetricBlockCipher.Camellia, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Camellia.ToString(),
                    DisplayName = "Camellia",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                _blockCipherDirectory.Add(SymmetricBlockCipher.Cast5, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Cast5.ToString(),
					DisplayName = "CAST-5 (CAST-128)",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128 },
                    DefaultKeySize = 128
                });
                _blockCipherDirectory.Add(SymmetricBlockCipher.Cast6, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Cast6.ToString(),
					DisplayName = "CAST-6 (CAST-256)",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 160, 192, 224, 256 },
                    DefaultKeySize = 256
                });
                _blockCipherDirectory.Add(SymmetricBlockCipher.Idea, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Idea.ToString(),
                    DisplayName = "International Data Encryption Algorithm (IDEA)",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                _blockCipherDirectory.Add(SymmetricBlockCipher.Noekeon, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Noekeon.ToString(),
                    DisplayName = "NOEKEON",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                _blockCipherDirectory.Add(SymmetricBlockCipher.Rc6, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Rc6.ToString(),
					DisplayName = "RC6",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });   
                _blockCipherDirectory.Add(SymmetricBlockCipher.Serpent, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Serpent.ToString(),
                    DisplayName = "Serpent",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
				_blockCipherDirectory.Add(SymmetricBlockCipher.Threefish, new SymmetricCipherDescription {
					Name = SymmetricBlockCipher.Threefish.ToString(),
					DisplayName = "Threefish",
					AllowableBlockSizes = new[] { 256, 512, 1024 },
					DefaultBlockSize = 256,
					AllowableKeySizes = new[] { 256, 512, 1024 },
					DefaultKeySize = 256
				});
                _blockCipherDirectory.Add(SymmetricBlockCipher.Twofish, new SymmetricCipherDescription {
                    Name = SymmetricBlockCipher.Twofish.ToString(),
                    DisplayName = "Twofish",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });

                // Add symmetric stream ciphers

                _streamCipherDirectory.Add(SymmetricStreamCipher.Hc128, new SymmetricCipherDescription {
                    Name = SymmetricStreamCipher.Hc128.ToString(),
                    DisplayName = "HC-128",
					AllowableBlockSizes = null,
                    DefaultBlockSize = -1,
                    AllowableIvSizes = new[] { 128 },
                    DefaultIvSize = 128,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                _streamCipherDirectory.Add(SymmetricStreamCipher.Hc256, new SymmetricCipherDescription {
                    Name = SymmetricStreamCipher.Hc256.ToString(),
                    DisplayName = "HC-256",
					AllowableBlockSizes = null,
                    DefaultBlockSize = -1,
					AllowableIvSizes = new[] { 128, 256 },
                    DefaultIvSize = 256,
					AllowableKeySizes = new[] { 128, 256 },
                    DefaultKeySize = 256
                });
#if INCLUDE_ISAAC
                _streamCipherDirectory.Add(SymmetricStreamCiphers.Isaac, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.Isaac.ToString(),
                    DisplayName = "Indirection, Shift, Accumulate, Add, and Count (ISAAC)",
					AllowableBlockSizes = null,
                    DefaultBlockSize = -1,
					AllowableIVSizes = new[] { -1 },
					DefaultIVSize = -1,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });
#endif
                _streamCipherDirectory.Add(SymmetricStreamCipher.Rabbit, new SymmetricCipherDescription {
                    Name = SymmetricStreamCipher.Rabbit.ToString(),
                    DisplayName = "Rabbit",
					AllowableBlockSizes = null,
                    DefaultBlockSize = -1,
                    AllowableIvSizes = new[] { 64 },
                    DefaultIvSize = 64,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
#if(INCLUDE_RC4)
                _streamCipherDirectory.Add(SymmetricStreamCipher.Rc4, new SymmetricCipherDescription {
					Name = SymmetricStreamCipher.Rc4.ToString(),
                    DisplayName = "RC4",
					AllowableBlockSizes = null,
                    DefaultBlockSize = -1,
					AllowableIvSizes = null,
					DefaultIvSize = -1,
					AllowableKeySizes = new[] { 40, 56, 64, 72, 96, 128, 192, 256 },
                    DefaultKeySize = 128
                });
#endif
                _streamCipherDirectory.Add(SymmetricStreamCipher.Salsa20, new SymmetricCipherDescription {
                    Name = SymmetricStreamCipher.Salsa20.ToString(),
                    DisplayName = "Salsa20",
					AllowableBlockSizes = null,
                    DefaultBlockSize = -1,
                    AllowableIvSizes = new[] { 64 },
                    DefaultIvSize = 64,
					AllowableKeySizes = new[] { 128, 256 },
                    DefaultKeySize = 256
                });
				_streamCipherDirectory.Add(SymmetricStreamCipher.ChaCha, new SymmetricCipherDescription {
					Name = SymmetricStreamCipher.ChaCha.ToString(),
					DisplayName = "ChaCha",
					AllowableBlockSizes = null,
					DefaultBlockSize = -1,
					AllowableIvSizes = new[] { 64 },
					DefaultIvSize = 64,
					AllowableKeySizes = new[] { 128, 256 },
					DefaultKeySize = 256
				});
				_streamCipherDirectory.Add(SymmetricStreamCipher.XSalsa20, new SymmetricCipherDescription {
					Name = SymmetricStreamCipher.XSalsa20.ToString(),
					DisplayName = "XSalsa20",
					AllowableBlockSizes = null,
					DefaultBlockSize = -1,
					AllowableIvSizes = new[] { 64, 128, 192 },
					DefaultIvSize = 192,
					AllowableKeySizes = new[] { 80, 128, 256 },
					DefaultKeySize = 256
				});
                _streamCipherDirectory.Add(SymmetricStreamCipher.Sosemanuk, new SymmetricCipherDescription {
                    Name = SymmetricStreamCipher.Sosemanuk.ToString(),
                    DisplayName = "SOSEMANUK",
					AllowableBlockSizes = null,
                    DefaultBlockSize = -1,
					AllowableIvSizes = new[] { 32, 48, 64, 80, 96, 112, 128 },
                    DefaultIvSize = 128,
					AllowableKeySizes = new[] { 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256 },
                    DefaultKeySize = 256
                });

                // Add block cipher modes of operation

                _blockCipherModeDirectory.Add(BlockCipherMode.Cbc, new SymmetricCipherModeDescription {
                    Name = BlockCipherMode.Cbc.ToString(),
                    DisplayName = "Ciphertext Block Chaining (CBC)",
                    PaddingRequirement = PaddingRequirement.Always,
                    AllowableBlockSizes = new[] { -1 },
					NonceReusePolicy = NoncePolicy.RequireRandom
                });
                _blockCipherModeDirectory.Add(BlockCipherMode.Cfb, new SymmetricCipherModeDescription {
                    Name = BlockCipherMode.Cfb.ToString(),
                    DisplayName = "Cipher Feedback (CFB)",
                    PaddingRequirement = PaddingRequirement.None,
                    AllowableBlockSizes = new[] { -1 },
					NonceReusePolicy = NoncePolicy.CounterAllowed
                });
                _blockCipherModeDirectory.Add(BlockCipherMode.Ctr, new SymmetricCipherModeDescription {
                    Name = BlockCipherMode.Ctr.ToString(),
					DisplayName = "Counter / Segmented Integer Counter (CTR/SIC)",
                    PaddingRequirement = PaddingRequirement.None,
                    AllowableBlockSizes = new[] { -1 },
					NonceReusePolicy = NoncePolicy.CounterAllowed
                });
                _blockCipherModeDirectory.Add(BlockCipherMode.Ofb, new SymmetricCipherModeDescription {
                    Name = BlockCipherMode.Ofb.ToString(),
                    DisplayName = "Output Feedback (OFB)",
                    PaddingRequirement = PaddingRequirement.None,
                    AllowableBlockSizes = new[] { -1 },
					NonceReusePolicy = NoncePolicy.CounterAllowed
                });

                // Add block cipher padding schemes

                _blockCipherPaddingDirectory.Add(BlockCipherPadding.Iso10126D2, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPadding.Iso10126D2.ToString(),
                    DisplayName = "ISO 10126-2"
                });
                _blockCipherPaddingDirectory.Add(BlockCipherPadding.Iso7816D4, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPadding.Iso7816D4.ToString(),
                    DisplayName = "ISO/IEC 7816-4"
                });
                _blockCipherPaddingDirectory.Add(BlockCipherPadding.Pkcs7, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPadding.Pkcs7.ToString(),
                    DisplayName = "PKCS 7"
                });
                _blockCipherPaddingDirectory.Add(BlockCipherPadding.Tbc, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPadding.Tbc.ToString(),
                    DisplayName = "Trailing Bit Complement (TBC)"
                });
                _blockCipherPaddingDirectory.Add(BlockCipherPadding.X923, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPadding.X923.ToString(),
                    DisplayName = "ANSI X.923"
                });

				// Add hash functions

				_hashFunctionDirectory.Add(HashFunction.Blake2B256, new HashFunctionDescription {
					Name = HashFunction.Blake2B256.ToString(),
					DisplayName = "BLAKE-2B-256",
					OutputSize = 256
				});
				_hashFunctionDirectory.Add(HashFunction.Blake2B384, new HashFunctionDescription {
					Name = HashFunction.Blake2B384.ToString(),
					DisplayName = "BLAKE-2B-384",
					OutputSize = 384
				});
				_hashFunctionDirectory.Add(HashFunction.Blake2B512, new HashFunctionDescription {
					Name = HashFunction.Blake2B512.ToString(),
					DisplayName = "BLAKE-2B-512",
					OutputSize = 512
				});
				_hashFunctionDirectory.Add(HashFunction.Keccak224, new HashFunctionDescription {
					Name = HashFunction.Keccak224.ToString(),
					DisplayName = "Keccak-224 (SHA-3-224)",
					OutputSize = 224
				});
				_hashFunctionDirectory.Add(HashFunction.Keccak256, new HashFunctionDescription {
					Name = HashFunction.Keccak256.ToString(),
					DisplayName = "Keccak-256 (SHA-3-256)",
					OutputSize = 256
				});
				_hashFunctionDirectory.Add(HashFunction.Keccak384, new HashFunctionDescription {
					Name = HashFunction.Keccak384.ToString(),
					DisplayName = "Keccak-384 (SHA-3-384)",
					OutputSize = 384
				});
				_hashFunctionDirectory.Add(HashFunction.Keccak512, new HashFunctionDescription {
					Name = HashFunction.Keccak512.ToString(),
					DisplayName = "Keccak-512 (SHA-3-512)",
					OutputSize = 512
				});
				_hashFunctionDirectory.Add(HashFunction.Ripemd160, new HashFunctionDescription {
					Name = HashFunction.Ripemd160.ToString(),
					DisplayName = "RIPEMD-160",
					OutputSize = 160
				});
#if INCLUDE_SHA1
				_hashFunctionDirectory.Add(HashFunction.Sha1, new HashFunctionDescription {
					Name = HashFunction.Sha1.ToString(),
					DisplayName = "SHA-1",
					OutputSize = 160
				});
#endif
				_hashFunctionDirectory.Add(HashFunction.Sha256, new HashFunctionDescription {
					Name = HashFunction.Sha256.ToString(),
					DisplayName = "SHA-2-256",
					OutputSize = 256
				});
				_hashFunctionDirectory.Add(HashFunction.Sha512, new HashFunctionDescription {
					Name = HashFunction.Sha512.ToString(),
					DisplayName = "SHA-2-512",
					OutputSize = 512
				});
				_hashFunctionDirectory.Add(HashFunction.Tiger, new HashFunctionDescription {
					Name = HashFunction.Tiger.ToString(),
					DisplayName = "Tiger",
					OutputSize = 192
				});

				// Add MAC functions

				_macFunctionDirectory.Add(MacFunction.Blake2B256, new MacFunctionDescription {
					Name = MacFunction.Blake2B256.ToString(),
					DisplayName = "BLAKE-2B-256",
					OutputSize = 256,
				});
				_macFunctionDirectory.Add(MacFunction.Blake2B384, new MacFunctionDescription {
					Name = MacFunction.Blake2B384.ToString(),
					DisplayName = "BLAKE-2B-384",
					OutputSize = 384,
				});
				_macFunctionDirectory.Add(MacFunction.Blake2B512, new MacFunctionDescription {
					Name = MacFunction.Blake2B512.ToString(),
					DisplayName = "BLAKE-2B-512",
					OutputSize = 512
				});
				_macFunctionDirectory.Add(MacFunction.Keccak224, new MacFunctionDescription {
					Name = MacFunction.Keccak224.ToString(),
					DisplayName = "Keccak-224 (SHA-3-224)",
					OutputSize = 224
				});
				_macFunctionDirectory.Add(MacFunction.Keccak256, new MacFunctionDescription {
					Name = MacFunction.Keccak256.ToString(),
					DisplayName = "Keccak-256 (SHA-3-256)",
					OutputSize = 256
				});
				_macFunctionDirectory.Add(MacFunction.Keccak384, new MacFunctionDescription {
					Name = MacFunction.Keccak384.ToString(),
					DisplayName = "Keccak-384 (SHA-3-384)",
					OutputSize = 384
				});
				_macFunctionDirectory.Add(MacFunction.Keccak512, new MacFunctionDescription {
					Name = MacFunction.Keccak512.ToString(),
					DisplayName = "Keccak-512 (SHA-3-512)",
					OutputSize = 512
				});
				_macFunctionDirectory.Add(MacFunction.Poly1305, new MacFunctionDescription {
					Name = MacFunction.Poly1305.ToString(),
					DisplayName = "Poly1305",
					OutputSize = 128
				});
				_macFunctionDirectory.Add(MacFunction.Cmac, new MacFunctionDescription {
					Name = MacFunction.Cmac.ToString(),
					DisplayName = "CMAC/OMAC1 construction",
					OutputSize = null
				});
				_macFunctionDirectory.Add(MacFunction.Hmac, new MacFunctionDescription {
					Name = MacFunction.Hmac.ToString(),
					DisplayName = "HMAC construction",
					OutputSize = null
				});

                // Add key derivation schemes

				_kdfDirectory.Add(KeyDerivationFunction.Pbkdf2, new KdfDescription {
					Name = KeyDerivationFunction.Pbkdf2.ToString(),
                    DisplayName = "Password-Based Key Derivation Function 2 (PBKDF2)"
                });
				_kdfDirectory.Add(KeyDerivationFunction.Scrypt, new KdfDescription {
					Name = KeyDerivationFunction.Scrypt.ToString(),
                    DisplayName = "Scrypt"
                });

                // Add CSPRNG functions

                _csprngDirectory.Add(CsPseudorandomNumberGenerator.Salsa20, new CsprngDescription {
                    Name = CsPseudorandomNumberGenerator.Salsa20.ToString(),
                    DisplayName = "Salsa20 cipher-based CSPRNG"
                });
				_csprngDirectory.Add(CsPseudorandomNumberGenerator.Sosemanuk, new CsprngDescription {
					Name = CsPseudorandomNumberGenerator.Sosemanuk.ToString(),
					DisplayName = "SOSEMANUK cipher-based CSPRNG"
				});
            }

            // Data storage.
            private static readonly Dictionary<SymmetricBlockCipher, SymmetricCipherDescription> _blockCipherDirectory =
                new Dictionary<SymmetricBlockCipher, SymmetricCipherDescription>();
            private static readonly Dictionary<SymmetricStreamCipher, SymmetricCipherDescription> _streamCipherDirectory =
                new Dictionary<SymmetricStreamCipher, SymmetricCipherDescription>();
            private static readonly Dictionary<BlockCipherMode, SymmetricCipherModeDescription> _blockCipherModeDirectory =
                new Dictionary<BlockCipherMode, SymmetricCipherModeDescription>();
            private static readonly Dictionary<BlockCipherPadding, SymmetricCipherPaddingDescription> _blockCipherPaddingDirectory =
                new Dictionary<BlockCipherPadding, SymmetricCipherPaddingDescription>();
            private static readonly Dictionary<HashFunction, HashFunctionDescription> _hashFunctionDirectory =
				new Dictionary<HashFunction, HashFunctionDescription>();
            private static readonly Dictionary<MacFunction, MacFunctionDescription> _macFunctionDirectory =
				new Dictionary<MacFunction, MacFunctionDescription>();
            private static readonly Dictionary<KeyDerivationFunction, KdfDescription> _kdfDirectory =
				new Dictionary<KeyDerivationFunction, KdfDescription>();
            private static readonly Dictionary<CsPseudorandomNumberGenerator, CsprngDescription> _csprngDirectory =
				new Dictionary<CsPseudorandomNumberGenerator, CsprngDescription>();
			
            // Exposure methods

            public static IReadOnlyDictionary<SymmetricBlockCipher, SymmetricCipherDescription> BlockCiphers {
                get { return _blockCipherDirectory; }
            }

            public static IReadOnlyDictionary<SymmetricStreamCipher, SymmetricCipherDescription> StreamCiphers {
                get { return _streamCipherDirectory; }
            }

            public static IReadOnlyDictionary<BlockCipherMode, SymmetricCipherModeDescription> BlockCipherModes {
                get { return _blockCipherModeDirectory; }
            }

            public static IReadOnlyDictionary<BlockCipherPadding, SymmetricCipherPaddingDescription> BlockCipherPaddings {
                get { return _blockCipherPaddingDirectory; }
            }

            public static IReadOnlyDictionary<HashFunction, HashFunctionDescription> HashFunctions {
                get { return _hashFunctionDirectory; }
            }

            public static IReadOnlyDictionary<MacFunction, MacFunctionDescription> MacFunctions {
                get { return _macFunctionDirectory; }
            }

            public static IReadOnlyDictionary<KeyDerivationFunction, KdfDescription> KeyDerivationFunctions {
                get { return _kdfDirectory; }
            }

            public static IReadOnlyDictionary<CsPseudorandomNumberGenerator, CsprngDescription> Csprngs {
                get { return _csprngDirectory; }
            }
        }

        public static class Packaging
        {
            public const int HeaderVersion = 1; // Version of DTO objects that code includes support for

            public const char PathDirectorySeperator = '/';
            
            public static byte[] GetHeaderTag() {
                return Encoding.UTF8.GetBytes("OCpkg-OHAI");
            }

            public static byte[] GetTrailerTag() {
                return Encoding.UTF8.GetBytes("KBAI-OCpkg");
            }
        }
    }
}