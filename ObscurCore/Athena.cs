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

using System;
using System.Collections.Generic;
using System.Linq;
using ObscurCore.Cryptography;
using ObscurCore.Packaging;

namespace ObscurCore
{
    /// <summary>
    /// Athena provides knowledge of how all core functions must be configured for proper operation, 
    /// and provides end-user-display-friendly names.
    /// </summary>
    public static class Athena
    {
        static Athena() {
            
        }

        public static class Cryptography
        {
            static Cryptography() {

                // Add symmetric block ciphers

                BlockCipherDirectory.Add(SymmetricBlockCiphers.AES, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.AES.ToString(),
                    DisplayName = "Advanced Encryption Standard (AES)",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.Blowfish, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Blowfish.ToString(),
                    DisplayName = "Blowfish",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
                    DefaultKeySize = 256
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.Camellia, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Camellia.ToString(),
                    DisplayName = "Camellia",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.CAST5, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.CAST5.ToString(),
                    DisplayName = "CAST-5 / CAST-128",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128 },
                    DefaultKeySize = 128
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.CAST6, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.CAST6.ToString(),
                    DisplayName = "CAST-6 / CAST-256",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 160, 192, 224, 256 },
                    DefaultKeySize = 256
                });

#if(INCLUDE_GOST28147)
                BlockCipherDirectory.Add(SymmetricBlockCiphers.GOST28147, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.GOST28147.ToString(),
                    DisplayName = "GOST 28147-89",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });
#endif

                BlockCipherDirectory.Add(SymmetricBlockCiphers.IDEA, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.IDEA.ToString(),
                    DisplayName = "International Data Encryption Algorithm (IDEA)",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.NOEKEON, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.NOEKEON.ToString(),
                    DisplayName = "NOEKEON",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.RC6, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.RC6.ToString(),
                    DisplayName = "RC6",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                
#if(INCLUDE_RIJNDAEL)
                BlockCiphers.Add(SymmetricBlockCiphers.Rijndael, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Rijndael.ToString(),
                    DisplayName = "Rijndael",
                    AllowableBlockSizes = new[] { 128, 192, 256 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
#endif

                BlockCipherDirectory.Add(SymmetricBlockCiphers.Serpent, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Serpent.ToString(),
                    DisplayName = "Serpent",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.TripleDES, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.TripleDES.ToString(),
                    DisplayName = "Triple DES (3DES, DESEDE; Triple Data Encryption Standard)",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 128, 192 },
                    DefaultKeySize = 192
                });
                BlockCipherDirectory.Add(SymmetricBlockCiphers.Twofish, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Twofish.ToString(),
                    DisplayName = "Twofish",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });

                // Add symmetric stream ciphers

                StreamCipherDirectory.Add(SymmetricStreamCiphers.HC128, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.HC128.ToString(),
                    DisplayName = "HC-128",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128 },
                    DefaultIVSize = 128,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                StreamCipherDirectory.Add(SymmetricStreamCiphers.HC256, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.HC256.ToString(),
                    DisplayName = "HC-256",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });

                StreamCipherDirectory.Add(SymmetricStreamCiphers.ISAAC, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.ISAAC.ToString(),
                    DisplayName = "Indirection, Shift, Accumulate, Add, and Count (ISAAC)",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });

                StreamCipherDirectory.Add(SymmetricStreamCiphers.Rabbit, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.Rabbit.ToString(),
                    DisplayName = "Rabbit",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 64 },
                    DefaultIVSize = 64,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });

#if(INCLUDE_RC4)
                StreamCipherDirectory.Add(SymmetricStreamCiphers.RC4, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.RC4,
                    DisplayName = "RC4",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 40, 56, 96, 128, 192, 256 },
                    DefaultIVSize = 128,
                    AllowableKeySizes = new[] { 40, 56, 96, 128, 192, 256 },
                    DefaultKeySize = 128
                });
#endif
 
                StreamCipherDirectory.Add(SymmetricStreamCiphers.Salsa20, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.Salsa20.ToString(),
                    DisplayName = "Salsa20",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 64 },
                    DefaultIVSize = 64,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });
                StreamCipherDirectory.Add(SymmetricStreamCiphers.SOSEMANUK, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.SOSEMANUK.ToString(),
                    DisplayName = "SOSEMANUK",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128 },
                    DefaultIVSize = 128,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });

#if(INCLUDE_VMPC)
                StreamCipherDirectory.Add(SymmetricStreamCiphers.VMPC, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.VMPC.ToString(),
                    DisplayName = "Variably Modified Permutation Composition (VMPC)",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128, 192, 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                StreamCipherDirectory.Add(SymmetricStreamCiphers.VMPC_KSA3, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.VMPC_KSA3.ToString(),
                    DisplayName = "Variably Modified Permutation Composition with Key Scheduling Algorithm 3 (VMPC-KSA3)",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128, 192, 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
#endif

                // Add block cipher modes of operation

                BlockCipherModeDirectory.Add(BlockCipherModes.CBC, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CBC.ToString(),
                    DisplayName = "Ciphertext Block Chaining (CBC)",
                    PaddingRequirement = PaddingRequirements.Always,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotApplicable
                });
                BlockCipherModeDirectory.Add(BlockCipherModes.CFB, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CFB.ToString(),
                    DisplayName = "Cipher Feedback (CFB)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                BlockCipherModeDirectory.Add(BlockCipherModes.CTR, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CTR.ToString(),
                    DisplayName = "Counter/Segmented Integer Counter (CTR/SIC)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                BlockCipherModeDirectory.Add(BlockCipherModes.CTS_CBC, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CTS_CBC.ToString(),
                    DisplayName = "Ciphertext Stealing with Ciphertext Block Chaining (CTS-CBC)",
                    PaddingRequirement = PaddingRequirements.IfUnderOneBlock,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotApplicable
                });
                BlockCipherModeDirectory.Add(BlockCipherModes.OFB, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.OFB.ToString(),
                    DisplayName = "Output Feedback (OFB)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                // Add AEAD modes of operation
                AEADBlockCipherModeDirectory.Add(AEADBlockCipherModes.EAX, new SymmetricCipherModeDescription {
                    Name = AEADBlockCipherModes.EAX.ToString(),
                    DisplayName = "Counter with OMAC (EAX)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { 64, 128, 192, 256 },
                    IsAEADMode = true,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                AEADBlockCipherModeDirectory.Add(AEADBlockCipherModes.GCM, new SymmetricCipherModeDescription {
                    Name = AEADBlockCipherModes.GCM.ToString(),
                    DisplayName = "Galois/Counter Mode (GCM)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { 128 },
                    IsAEADMode = true,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                // TODO: Implement OCB mode
                /*
                AEADBlockCipherModeDirectory.Add(AEADBlockCipherModes.OCB, new SymmetricCipherModeDescription {
                    Name = AEADBlockCipherModes.OCB.ToString(),
                    DisplayName = "Offset Codebook (OCB)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { 128, 192, 256 },
                    IsAEADMode = true,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                */
				// TODO: Implement SIV mode
				/*
                AEADBlockCipherModeDirectory.Add(AEADBlockCipherModes.SIV, new SymmetricCipherModeDescription {
                    Name = AEADBlockCipherModes.SIV.ToString(),
                    DisplayName = "Synthetic Initialisation Vector (SIV)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { 128, 192, 256 },
                    IsAEADMode = true,
                    NonceReusePolicy = NonceReusePolicies.Allowed
                });
                */

                // Add block cipher padding schemes

                BlockCipherPaddingDirectory.Add(BlockCipherPaddings.ISO10126D2, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.ISO10126D2.ToString(),
                    DisplayName = "ISO 10126-2"
                });
                BlockCipherPaddingDirectory.Add(BlockCipherPaddings.ISO7816D4, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.ISO7816D4.ToString(),
                    DisplayName = "ISO/IEC 7816-4"
                });
                BlockCipherPaddingDirectory.Add(BlockCipherPaddings.PKCS7, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.PKCS7.ToString(),
                    DisplayName = "PKCS 7"
                });
                BlockCipherPaddingDirectory.Add(BlockCipherPaddings.TBC, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.TBC.ToString(),
                    DisplayName = "Trailing Bit Complement (TBC)"
                });
                BlockCipherPaddingDirectory.Add(BlockCipherPaddings.X923, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.X923.ToString(),
                    DisplayName = "ANSI X.923"
                });

				// Add hash functions

				HashFunctionDirectory.Add(HashFunctions.BLAKE2B256, new HashFunctionDescription {
					Name = HashFunctions.BLAKE2B256.ToString(),
					DisplayName = "BLAKE-2B-256",
					OutputSize = 256
				});
				HashFunctionDirectory.Add(HashFunctions.BLAKE2B384, new HashFunctionDescription {
					Name = HashFunctions.BLAKE2B384.ToString(),
					DisplayName = "BLAKE-2B-384",
					OutputSize = 384
				});
				HashFunctionDirectory.Add(HashFunctions.BLAKE2B512, new HashFunctionDescription {
					Name = HashFunctions.BLAKE2B512.ToString(),
					DisplayName = "BLAKE-2B-512",
					OutputSize = 512
				});
				HashFunctionDirectory.Add(HashFunctions.Keccak224, new HashFunctionDescription {
					Name = HashFunctions.Keccak224.ToString(),
					DisplayName = "Keccak-224 / SHA-3-224",
					OutputSize = 224
				});
				HashFunctionDirectory.Add(HashFunctions.Keccak256, new HashFunctionDescription {
					Name = HashFunctions.Keccak256.ToString(),
					DisplayName = "Keccak-256 / SHA-3-256",
					OutputSize = 256
				});
				HashFunctionDirectory.Add(HashFunctions.Keccak384, new HashFunctionDescription {
					Name = HashFunctions.Keccak384.ToString(),
					DisplayName = "Keccak-384 / SHA-3-384",
					OutputSize = 384
				});
				HashFunctionDirectory.Add(HashFunctions.Keccak512, new HashFunctionDescription {
					Name = HashFunctions.Keccak512.ToString(),
					DisplayName = "Keccak-512 / SHA-3-512",
					OutputSize = 512
				});
				HashFunctionDirectory.Add(HashFunctions.RIPEMD160, new HashFunctionDescription {
					Name = HashFunctions.RIPEMD160.ToString(),
					DisplayName = "RIPEMD-160",
					OutputSize = 160
				});
				HashFunctionDirectory.Add(HashFunctions.SHA1, new HashFunctionDescription {
					Name = HashFunctions.SHA1.ToString(),
					DisplayName = "SHA-1",
					OutputSize = 96
				});
				HashFunctionDirectory.Add(HashFunctions.SHA256, new HashFunctionDescription {
					Name = HashFunctions.SHA256.ToString(),
					DisplayName = "SHA-2-256",
					OutputSize = 256
				});
				HashFunctionDirectory.Add(HashFunctions.SHA384, new HashFunctionDescription {
					Name = HashFunctions.SHA384.ToString(),
					DisplayName = "SHA-2-384",
					OutputSize = 384
				});
				HashFunctionDirectory.Add(HashFunctions.SHA512, new HashFunctionDescription {
					Name = HashFunctions.SHA512.ToString(),
					DisplayName = "SHA-2-512",
					OutputSize = 512
				});
				HashFunctionDirectory.Add(HashFunctions.Tiger, new HashFunctionDescription {
					Name = HashFunctions.Tiger.ToString(),
					DisplayName = "Tiger",
					OutputSize = 192
				});
				HashFunctionDirectory.Add(HashFunctions.Whirlpool, new HashFunctionDescription {
					Name = HashFunctions.Whirlpool.ToString(),
					DisplayName = "Whirlpool",
					OutputSize = 512
				});

				// Add MAC functions

				MACFunctionDirectory.Add(MACFunctions.BLAKE2B256, new MACFunctionDescription {
					Name = MACFunctions.BLAKE2B256.ToString(),
					DisplayName = "BLAKE-2B-256",
					OutputSize = 256,
					SaltSupported = true
				});
				MACFunctionDirectory.Add(MACFunctions.BLAKE2B384, new MACFunctionDescription {
					Name = MACFunctions.BLAKE2B384.ToString(),
					DisplayName = "BLAKE-2B-384",
					OutputSize = 384,
					SaltSupported = true
				});
				MACFunctionDirectory.Add(MACFunctions.BLAKE2B512, new MACFunctionDescription {
					Name = MACFunctions.BLAKE2B512.ToString(),
					DisplayName = "BLAKE-2B-512",
					OutputSize = 512,
					SaltSupported = true
				});
				MACFunctionDirectory.Add(MACFunctions.Keccak224, new MACFunctionDescription {
					Name = MACFunctions.Keccak224.ToString(),
					DisplayName = "Keccak-224 / SHA-3-224",
					OutputSize = 224,
					SaltSupported = true
				});
				MACFunctionDirectory.Add(MACFunctions.Keccak256, new MACFunctionDescription {
					Name = MACFunctions.Keccak256.ToString(),
					DisplayName = "Keccak-256 / SHA-3-256",
					OutputSize = 256,
					SaltSupported = true
				});
				MACFunctionDirectory.Add(MACFunctions.Keccak384, new MACFunctionDescription {
					Name = MACFunctions.Keccak384.ToString(),
					DisplayName = "Keccak-384 / SHA-3-384",
					OutputSize = 384,
					SaltSupported = true
				});
				MACFunctionDirectory.Add(MACFunctions.Keccak512, new MACFunctionDescription {
					Name = MACFunctions.Keccak512.ToString(),
					DisplayName = "Keccak-512 / SHA-3-512",
					OutputSize = 512,
					SaltSupported = true
				});
				MACFunctionDirectory.Add(MACFunctions.CMAC, new MACFunctionDescription {
					Name = MACFunctions.CMAC.ToString(),
					DisplayName = "CMAC / OMAC1 construction",
					OutputSize = null,
					SaltSupported = false
				});
				MACFunctionDirectory.Add(MACFunctions.HMAC, new MACFunctionDescription {
					Name = MACFunctions.HMAC.ToString(),
					DisplayName = "HMAC construction",
					OutputSize = null,
					SaltSupported = false
				});

                // Add key derivation schemes

				KDFDirectory.Add(KeyDerivationFunctions.PBKDF2, new KDFDescription {
					Name = KeyDerivationFunctions.PBKDF2.ToString(),
                    DisplayName = "Password-Based Key Derivation Function 2 (PBKDF2)"
                });
				KDFDirectory.Add(KeyDerivationFunctions.Scrypt, new KDFDescription {
					Name = KeyDerivationFunctions.Scrypt.ToString(),
                    DisplayName = "scrypt"
                });

                // Add CSPRNG functions

                PRNGDirectory.Add(CSPRNumberGenerators.Salsa20, new CSPRNGDescription {
                    Name = CSPRNumberGenerators.Salsa20.ToString(),
                    DisplayName = "Salsa20 cipher based CSPRNG"
                });
				PRNGDirectory.Add(CSPRNumberGenerators.SOSEMANUK, new CSPRNGDescription {
					Name = CSPRNumberGenerators.SOSEMANUK.ToString(),
					DisplayName = "SOSEMANUK cipher based CSPRNG"
				});
            }

            // Data storage.
            internal static Dictionary<SymmetricBlockCiphers, SymmetricCipherDescription> BlockCipherDirectory =
                new Dictionary<SymmetricBlockCiphers, SymmetricCipherDescription>();
            internal static Dictionary<SymmetricStreamCiphers, SymmetricCipherDescription> StreamCipherDirectory =
                new Dictionary<SymmetricStreamCiphers, SymmetricCipherDescription>();
            internal static Dictionary<BlockCipherModes, SymmetricCipherModeDescription> BlockCipherModeDirectory =
                new Dictionary<BlockCipherModes, SymmetricCipherModeDescription>();
            internal static Dictionary<AEADBlockCipherModes, SymmetricCipherModeDescription> AEADBlockCipherModeDirectory =
                new Dictionary<AEADBlockCipherModes, SymmetricCipherModeDescription>();
            internal static Dictionary<BlockCipherPaddings, SymmetricCipherPaddingDescription> BlockCipherPaddingDirectory =
                new Dictionary<BlockCipherPaddings, SymmetricCipherPaddingDescription>();
			internal static Dictionary<HashFunctions, HashFunctionDescription> HashFunctionDirectory =
				new Dictionary<HashFunctions, HashFunctionDescription>();
            internal static Dictionary<MACFunctions, MACFunctionDescription> MACFunctionDirectory =
				new Dictionary<MACFunctions, MACFunctionDescription>();
			internal static Dictionary<KeyDerivationFunctions, KDFDescription> KDFDirectory =
				new Dictionary<KeyDerivationFunctions, KDFDescription>();
			internal static Dictionary<CSPRNumberGenerators, CSPRNGDescription> PRNGDirectory =
				new Dictionary<CSPRNumberGenerators, CSPRNGDescription>();
			
            // Query functions
            public static bool IsSymmetricCipherSupported(string name) {
                return Enum.GetNames(typeof (SymmetricBlockCiphers)).Contains(name) ||
                    Enum.GetNames(typeof (SymmetricBlockCiphers)).Contains(name);
            }

            public static bool IsModeSupported(string name) {
                return Enum.GetNames(typeof (BlockCipherModes)).Contains(name) ||
                    Enum.GetNames(typeof (AEADBlockCipherModes)).Contains(name);
            }

            public static bool IsSymmetricPaddingSupported(string name) {
                return Enum.GetNames(typeof (BlockCipherPaddings)).Contains(name);
            }
        }
    }

    public sealed class SymmetricCipherDescription
    {
        /// <summary>
        /// Name of the cryptographic cipher transform (must be a member of SymmetricBlockCiphers or SymmetricStreamCiphers).
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        /// Name to show a user or for a detailed specification.
        /// </summary>
        public string DisplayName { get; internal set; }

        /// <summary>
        /// Array of allowable sizes (in bits) for the block size of the cipher, where applicable. Set to -1 if stream cipher.
        /// </summary>
        public int[] AllowableBlockSizes { get; internal set; }

        /// <summary>
        /// If no block size size is supplied when configuring the cipher, this is the size that should be used, where applicable. Set to -1 if stream cipher.
        /// </summary>
        public int DefaultBlockSize { get; internal set; }

        /// <summary>
        /// Array of allowable sizes (in bits) for the cipher initialisation vector (IV).
        /// </summary>
        public int[] AllowableIVSizes { get; internal set; }

        /// <summary>
        /// If no IV size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultIVSize { get; internal set; }

        /// <summary>
        /// Array of allowable sizes (in bits) for the cryptographic key.
        /// </summary>
        public int[] AllowableKeySizes { get; internal set; }

        /// <summary>
        /// If no key size is supplied when configuring the cipher, this is the size that should be used.
        /// </summary>
        public int DefaultKeySize { get; internal set; }
    }

    public sealed class SymmetricCipherModeDescription
    {
        /// <summary>
        /// Name of the cryptographic cipher mode (must be a member of BlockCipherModes or AEADBlockCipherModes).
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        /// Name to show a user or for a detailed specification.
        /// </summary>
        public string DisplayName { get; internal set; }

        /// <summary>
        /// Array of allowable sizes (in bits) for the block size of the cipher. Set to -1 if unrestricted.
        /// </summary>
        public int[] AllowableBlockSizes { get; internal set; }

        /// <summary>
        /// Whether this mode requires padding.
        /// </summary>
        public PaddingRequirements PaddingRequirement { get; internal set; }

        /// <summary>
        /// Whether this mode is of the Authenticated Encryption/Decryption type.
        /// </summary>
        public bool IsAEADMode { get; internal set; }

        /// <summary>
        /// Whether the nonce/IV can be re-used in a later encryption operation, where data 
        /// will travel over the same channel, or otherwise might be subjected to analysis.
        /// </summary>
        public NonceReusePolicies NonceReusePolicy { get; internal set; }
    }

    public enum PaddingRequirements
    {
        None = 0,
        /// <summary>
        /// Padding scheme must be used if plaintext length is less than 1 block length.
        /// </summary>
        IfUnderOneBlock,
        /// <summary>
        /// Self-explanatory.
        /// </summary>
        Always
    }

    public enum NonceReusePolicies
    {
        NotApplicable = 0,
        /// <summary>
        /// Nonce reuse may result in total or partial loss of security properties.
        /// </summary>
        NotAllowed,
        /// <summary>
        /// Construction of operation mode allows nonce reuse without catastrophic security loss, 
        /// but better security properties will be obtained by ensuring a new nonce is used each time.
        /// </summary>
        Allowed
    }

    public sealed class SymmetricCipherPaddingDescription
    {
        /// <summary>
        /// Name of the block cipher padding scheme (must be a member of BlockCipherPaddingTypes).
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        /// Name to show a user or for a detailed specification.
        /// </summary>
        public string DisplayName { get; internal set; }
    }

	public sealed class KDFDescription
	{
		/// <summary>
		/// Name of the KDF scheme (must be a member of KDFDirectory).
		/// </summary>
        public string Name { get; internal set; }

		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
        public string DisplayName { get; internal set; }
	}

	public sealed class CSPRNGDescription
	{	
		/// <summary>
		/// Name of the CSPRNG scheme (must be a member of CSPRNumberGenerators).
		/// </summary>
		public string Name { get; internal set; }
		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
		public string DisplayName { get; internal set; }
	}

	public sealed class HashFunctionDescription
	{	
        /// <summary>
        /// Name of the hash function (must be a member of HashFunctionDirectory).
        /// </summary>
		public string Name { get; internal set; }
		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
		public string DisplayName { get; internal set; }

		/// <summary>
		/// Size of the hash/digest produced in bits.
		/// </summary>
		public int OutputSize { get; internal set; }
	}

	public sealed class MACFunctionDescription
	{
        /// <summary>
        /// Name of the MAC function (must be a member of MACFunctionDirectory).
        /// </summary>
		public string Name { get; internal set; }
		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
		public string DisplayName { get; internal set; }

		/// <summary>
		/// Size of the MAC produced in bits. Null if output size depends on configuration.
		/// </summary>
		public int? OutputSize { get; internal set; }

		/// <summary>
		/// Whether the MAC operation may include special salting operation.
		/// </summary>
		public bool SaltSupported { get; internal set; }
	}	
}