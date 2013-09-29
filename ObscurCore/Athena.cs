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
using System.IO;
using System.Linq;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Extensions.Enumerations;
using ObscurCore.Packaging;

namespace ObscurCore
{
    /// <summary>
    /// Athena provides knowledge of how all core functions must be configured for proper operation 
	/// and provides low friction instantiation facilities for core objects.
    /// </summary>
    public static class Athena
    {
        static Athena() {
            
        }

        public static class Cryptography
        {
            static Cryptography() {
                // Add all symmetric block ciphers
                BlockCiphers.Add(SymmetricBlockCiphers.AES, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.AES.ToString(),
                    DisplayName = "Advanced Encryption Standard (AES)",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                BlockCiphers.Add(SymmetricBlockCiphers.Blowfish, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Blowfish.ToString(),
                    DisplayName = "Blowfish",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
                    DefaultKeySize = 256
                });
                BlockCiphers.Add(SymmetricBlockCiphers.Camellia, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Camellia.ToString(),
                    DisplayName = "Camellia",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                BlockCiphers.Add(SymmetricBlockCiphers.CAST5, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.CAST5.ToString(),
                    DisplayName = "CAST-5 / CAST-128",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128 },
                    DefaultKeySize = 128
                });
                BlockCiphers.Add(SymmetricBlockCiphers.CAST6, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.CAST6.ToString(),
                    DisplayName = "CAST-6 / CAST-256",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 160, 192, 224, 256 },
                    DefaultKeySize = 256
                });
                /*
                BlockCiphers.Add(SymmetricBlockCiphers.GOST28147, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.GOST28147.ToString(),
                    DisplayName = "GOST 28147-89",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });
                */
                BlockCiphers.Add(SymmetricBlockCiphers.IDEA, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.IDEA.ToString(),
                    DisplayName = "IDEA",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                BlockCiphers.Add(SymmetricBlockCiphers.NOEKEON, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.NOEKEON.ToString(),
                    DisplayName = "NOEKEON",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                BlockCiphers.Add(SymmetricBlockCiphers.RC6, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.RC6.ToString(),
                    DisplayName = "RC6",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                /*
                BlockCiphers.Add(SymmetricBlockCiphers.Rijndael, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Rijndael.ToString(),
                    DisplayName = "Rijndael",
                    AllowableBlockSizes = new[] { 128, 192, 256 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                */
                BlockCiphers.Add(SymmetricBlockCiphers.Serpent, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Serpent.ToString(),
                    DisplayName = "Serpent",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                BlockCiphers.Add(SymmetricBlockCiphers.TripleDES, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.TripleDES.ToString(),
                    DisplayName = "Triple DES / 3DES / DESEDE",
                    AllowableBlockSizes = new[] { 64 },
                    DefaultBlockSize = 64,
                    AllowableKeySizes = new[] { 128, 192 },
                    DefaultKeySize = 192
                });
                BlockCiphers.Add(SymmetricBlockCiphers.Twofish, new SymmetricCipherDescription {
                    Name = SymmetricBlockCiphers.Twofish.ToString(),
                    DisplayName = "Twofish",
                    AllowableBlockSizes = new[] { 128 },
                    DefaultBlockSize = 128,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });

                // Add all symmetric stream ciphers

                StreamCiphers.Add(SymmetricStreamCiphers.HC128, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.HC128.ToString(),
                    DisplayName = "HC-128",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128 },
                    DefaultIVSize = 128,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });
                StreamCiphers.Add(SymmetricStreamCiphers.HC256, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.HC256.ToString(),
                    DisplayName = "HC-256",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });

                StreamCiphers.Add(SymmetricStreamCiphers.ISAAC, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.HC256.ToString(),
                    DisplayName = "HC-256",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });

                StreamCiphers.Add(SymmetricStreamCiphers.Rabbit, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.Rabbit.ToString(),
                    DisplayName = "Rabbit",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 64 },
                    DefaultIVSize = 64,
                    AllowableKeySizes = new[] { 128 },
                    DefaultKeySize = 128
                });

                /*
                StreamCiphers.Add(SymmetricStreamCiphers.RC4, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.RC4,
                    DisplayName = "RC4",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 40, 56, 96, 128, 192, 256 },
                    DefaultIVSize = 128,
                    AllowableKeySizes = new[] { 40, 56, 96, 128, 192, 256 },
                    DefaultKeySize = 128
                });
                */
 
                StreamCiphers.Add(SymmetricStreamCiphers.Salsa20, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.Salsa20.ToString(),
                    DisplayName = "Salsa20",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 64 },
                    DefaultIVSize = 64,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });
                StreamCiphers.Add(SymmetricStreamCiphers.SOSEMANUK, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.SOSEMANUK.ToString(),
                    DisplayName = "SOSEMANUK",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128 },
                    DefaultIVSize = 128,
                    AllowableKeySizes = new[] { 256 },
                    DefaultKeySize = 256
                });

                /*
                StreamCiphers.Add(SymmetricStreamCiphers.VMPC, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.VMPC.ToString(),
                    DisplayName = "Variably Modified Permutation Composition (VMPC)",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128, 192, 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                StreamCiphers.Add(SymmetricStreamCiphers.VMPC_KSA3, new SymmetricCipherDescription {
                    Name = SymmetricStreamCiphers.VMPC_KSA3.ToString(),
                    DisplayName = "Variably Modified Permutation Composition with Key Scheduling Algorithm 3 (VMPC-KSA3)",
                    AllowableBlockSizes = new[] { -1 },
                    DefaultBlockSize = -1,
                    AllowableIVSizes = new[] { 128, 192, 256 },
                    DefaultIVSize = 256,
                    AllowableKeySizes = new[] { 128, 192, 256 },
                    DefaultKeySize = 256
                });
                */

                // Add block cipher modes of operation
                BlockModes.Add(BlockCipherModes.CBC, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CBC.ToString(),
                    DisplayName = "Ciphertext Block Chaining (CBC)",
                    PaddingRequirement = PaddingRequirements.Always,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotApplicable
                });
                BlockModes.Add(BlockCipherModes.CFB, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CFB.ToString(),
                    DisplayName = "Cipher Feedback (CFB)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotApplicable
                });
                BlockModes.Add(BlockCipherModes.CTR, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CTR.ToString(),
                    DisplayName = "Counter/Segmented Integer Counter (CTR/SIC)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotApplicable
                });
                BlockModes.Add(BlockCipherModes.CTS_CBC, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.CTS_CBC.ToString(),
                    DisplayName = "Ciphertext Stealing with Ciphertext Block Chaining (CTS-CBC)",
                    PaddingRequirement = PaddingRequirements.IfUnderOneBlock,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotApplicable
                });
                BlockModes.Add(BlockCipherModes.OFB, new SymmetricCipherModeDescription {
                    Name = BlockCipherModes.OFB.ToString(),
                    DisplayName = "Output Feedback (OFB)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { -1 },
                    IsAEADMode = false,
                    NonceReusePolicy = NonceReusePolicies.NotApplicable
                });
                // Add AEAD modes of operation
                AEADBlockModes.Add(AEADBlockCipherModes.EAX, new SymmetricCipherModeDescription {
                    Name = AEADBlockCipherModes.EAX.ToString(),
                    DisplayName = "Counter with OMAC (EAX)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { 64, 128, 192, 256 },
                    IsAEADMode = true,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                AEADBlockModes.Add(AEADBlockCipherModes.GCM, new SymmetricCipherModeDescription {
                    Name = AEADBlockCipherModes.GCM.ToString(),
                    DisplayName = "Galois/Counter Mode (GCM)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { 128 },
                    IsAEADMode = true,
                    NonceReusePolicy = NonceReusePolicies.NotAllowed
                });
                // TODO: Implement OCB mode
                /*
                AEADBlockModes.Add(AEADBlockCipherModes.OCB, new SymmetricCipherModeDescription {
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
                AEADBlockModes.Add(AEADBlockCipherModes.SIV, new SymmetricCipherModeDescription {
                    Name = AEADBlockCipherModes.SIV.ToString(),
                    DisplayName = "Synthetic Initialisation Vector (SIV)",
                    PaddingRequirement = PaddingRequirements.None,
                    AllowableBlockSizes = new[] { 128, 192, 256 },
                    IsAEADMode = true,
                    NonceReusePolicy = NonceReusePolicies.Allowed
                });
                */

                // Add block cipher padding schemes
                BlockPaddings.Add(BlockCipherPaddings.ISO10126D2, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.ISO10126D2.ToString(),
                    DisplayName = "ISO 10126-2"
                });
                BlockPaddings.Add(BlockCipherPaddings.ISO7816D4, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.ISO7816D4.ToString(),
                    DisplayName = "ISO/IEC 7816-4"
                });
                BlockPaddings.Add(BlockCipherPaddings.PKCS7, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.PKCS7.ToString(),
                    DisplayName = "PKCS 7"
                });
                BlockPaddings.Add(BlockCipherPaddings.TBC, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.TBC.ToString(),
                    DisplayName = "Trailing Bit Complement (TBC)"
                });
                BlockPaddings.Add(BlockCipherPaddings.X923, new SymmetricCipherPaddingDescription {
                    Name = BlockCipherPaddings.X923.ToString(),
                    DisplayName = "ANSI X.923"
                });



                // Add key derivation schemes
				KeyDerivationFunctions.Add(ObscurCore.Cryptography.KeyDerivationFunctions.PBKDF2, new KDFDescription {
					Name = ObscurCore.Cryptography.KeyDerivationFunctions.PBKDF2.ToString(),
                    DisplayName = "Password Based Key Derivation Function 2 (PBKDF2)"
                });
				KeyDerivationFunctions.Add(ObscurCore.Cryptography.KeyDerivationFunctions.Scrypt, new KDFDescription {
					Name = ObscurCore.Cryptography.KeyDerivationFunctions.Scrypt.ToString(),
                    DisplayName = "scrypt"
                });

                // Add PRNGs
                PRNGs.Add(CSPRNumberGenerators.Salsa20, new CSPRNGDescription {
                    Name = CSPRNumberGenerators.Salsa20.ToString(),
                    DisplayName = "Salsa20 cipher based CSPRNG"
                });
				PRNGs.Add(CSPRNumberGenerators.SOSEMANUK, new CSPRNGDescription {
					Name = CSPRNumberGenerators.SOSEMANUK.ToString(),
					DisplayName = "SOSEMANUK cipher based CSPRNG"
				});
            }

            // Data storage.
            internal static Dictionary<SymmetricBlockCiphers, SymmetricCipherDescription> BlockCiphers =
                new Dictionary<SymmetricBlockCiphers, SymmetricCipherDescription>();
            internal static Dictionary<SymmetricStreamCiphers, SymmetricCipherDescription> StreamCiphers =
                new Dictionary<SymmetricStreamCiphers, SymmetricCipherDescription>();
            internal static Dictionary<BlockCipherModes, SymmetricCipherModeDescription> BlockModes =
                new Dictionary<BlockCipherModes, SymmetricCipherModeDescription>();
            internal static Dictionary<AEADBlockCipherModes, SymmetricCipherModeDescription> AEADBlockModes =
                new Dictionary<AEADBlockCipherModes, SymmetricCipherModeDescription>();
            internal static Dictionary<BlockCipherPaddings, SymmetricCipherPaddingDescription> BlockPaddings =
                new Dictionary<BlockCipherPaddings, SymmetricCipherPaddingDescription>();
			internal static Dictionary<HashFunctions, HashFunctionDescription> HashFunctions =
				new Dictionary<HashFunctions, HashFunctionDescription>();
            internal static Dictionary<MACFunctions, MACFunctionDescription> MACFunctions =
				new Dictionary<MACFunctions, MACFunctionDescription>();
			internal static Dictionary<KeyDerivationFunctions, KDFDescription> KeyDerivationFunctions =
				new Dictionary<KeyDerivationFunctions, KDFDescription>();
			internal static Dictionary<CSPRNumberGenerators, CSPRNGDescription> PRNGs =
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

		public static class Packaging
		{
			static Packaging () {
				// Add all symmetric block ciphers
				PayloadModules.Add (PayloadLayoutSchemes.Simple.ToString (), new PayloadModuleDescription {
					Name = PayloadLayoutSchemes.Simple.ToString(),
					DisplayName = PayloadLayoutSchemes.Simple.ToString()
				});
				PayloadModules.Add (PayloadLayoutSchemes.Frameshift.ToString (), new PayloadModuleDescription {
					Name = PayloadLayoutSchemes.Frameshift.ToString(),
					DisplayName = PayloadLayoutSchemes.Frameshift.ToString()
				});
#if(INCLUDE_FABRIC)
                PayloadModules.Add (PayloadLayoutSchemes.Fabric.ToString (), new PayloadModuleDescription {
					Name = PayloadLayoutSchemes.Fabric.ToString(),
					DisplayName = PayloadLayoutSchemes.Fabric.ToString()
				});
#endif
			}
			
			// Data storage.
			public static Dictionary<string, PayloadModuleDescription> PayloadModules =
				new Dictionary<string, PayloadModuleDescription>();
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
		/// Name of the KDF scheme (must be a member of KeyDerivationFunctions).
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
        /// Name of the hash function (must be a member of HashFunctions).
        /// </summary>
		public string Name { get; internal set; }
		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
		public string DisplayName { get; internal set; }
	}

	public sealed class MACFunctionDescription
	{
        /// <summary>
        /// Name of the [H]MAC function (must be a member of MACFunctions).
        /// </summary>
		public string Name { get; internal set; }
		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
		public string DisplayName { get; internal set; }

		/// <summary>
		/// Whether the MAC operation may include special salting operation.
		/// </summary>
		public bool SaltSupported { get; internal set; }
	}

    // Packaging related

	public sealed class PayloadModuleDescription
	{
		/// <summary>
		/// Name of the payload layout scheme (must be a member of PayloadLayoutSchemes).
		/// </summary>
		public string Name { get; internal set; }
		/// <summary>
		/// Name to show a user or for a detailed specification.
		/// </summary>
		public string DisplayName { get; internal set; }

		public override string ToString () {
			return string.Format ("Payload Layout Scheme & Stream Multiplexer: {0}", DisplayName);
		}
	}
}