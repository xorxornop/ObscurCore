using System.Collections.Generic;
using System.Collections.Immutable;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Information;
using ObscurCore.Cryptography.Ciphers.Stream;

namespace ObscurCore.Cryptography.Ciphers
{
    internal static class CipherInformationStore
    {
        internal static readonly ImmutableDictionary<BlockCipher, BlockCipherInformation> BlockCipherDictionary;
        internal static readonly ImmutableDictionary<BlockCipherMode, BlockCipherModeInformation> BlockCipherModeDictionary;
        internal static readonly ImmutableDictionary<BlockCipherPadding, BlockCipherPaddingInformation> BlockCipherPaddingDictionary;
        internal static readonly ImmutableDictionary<StreamCipher, StreamCipherInformation> StreamCipherDictionary;

        static CipherInformationStore()
        {
            BlockCipherDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Aes, new BlockCipherInformation {
                        Name = BlockCipher.Aes.ToString(),
                        DisplayName = "Advanced Encryption Standard (AES)",
                        AllowableBlockSizes = new[] { 128 },
                        DefaultBlockSize = 128,
                        AllowableKeySizes = new[] { 128, 192, 256 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Blowfish, new BlockCipherInformation {
                        Name = BlockCipher.Blowfish.ToString(),
                        DisplayName = "Blowfish",
                        AllowableBlockSizes = new[] { 64 },
                        DefaultBlockSize = 64,
                        AllowableKeySizes =
                            new[] { 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Camellia, new BlockCipherInformation {
                        Name = BlockCipher.Camellia.ToString(),
                        DisplayName = "Camellia",
                        AllowableBlockSizes = new[] { 128 },
                        DefaultBlockSize = 128,
                        AllowableKeySizes = new[] { 128, 192, 256 },
                        DefaultKeySize = 256
#if INCLUDE_IDEA
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Idea, new BlockCipherInformation {
                        Name = BlockCipher.Idea.ToString(),
                        DisplayName = "International Data Encryption Algorithm (IDEA)",
                        AllowableBlockSizes = new[] { 64 },
                        DefaultBlockSize = 64,
                        AllowableKeySizes = new[] { 128 },
                        DefaultKeySize = 128
#endif
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Noekeon, new BlockCipherInformation {
                        Name = BlockCipher.Noekeon.ToString(),
                        DisplayName = "NOEKEON",
                        AllowableBlockSizes = new[] { 128 },
                        DefaultBlockSize = 128,
                        AllowableKeySizes = new[] { 128 },
                        DefaultKeySize = 128
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Rc6, new BlockCipherInformation {
                        Name = BlockCipher.Rc6.ToString(),
                        DisplayName = "RC6",
                        AllowableBlockSizes = new[] { 128 },
                        DefaultBlockSize = 128,
                        AllowableKeySizes = new[] { 128, 192, 256 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Serpent, new BlockCipherInformation {
                        Name = BlockCipher.Serpent.ToString(),
                        DisplayName = "Serpent",
                        AllowableBlockSizes = new[] { 128 },
                        DefaultBlockSize = 128,
                        AllowableKeySizes = new[] { 128, 192, 256 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Threefish, new BlockCipherInformation {
                        Name = BlockCipher.Threefish.ToString(),
                        DisplayName = "Threefish",
                        AllowableBlockSizes = new[] { 256, 512, 1024 },
                        DefaultBlockSize = 256,
                        AllowableKeySizes = new[] { 256, 512, 1024 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Twofish, new BlockCipherInformation {
                        Name = BlockCipher.Twofish.ToString(),
                        DisplayName = "Twofish",
                        AllowableBlockSizes = new[] { 128 },
                        DefaultBlockSize = 128,
                        AllowableKeySizes = new[] { 128, 192, 256 },
                        DefaultKeySize = 256
                    })
            });

            StreamCipherDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Hc128, new StreamCipherInformation {
                        Name = StreamCipher.Hc128.ToString(),
                        DisplayName = "HC-128",
                        AllowableNonceSizes = new[] { 128 },
                        DefaultNonceSize = 128,
                        AllowableKeySizes = new[] { 128 },
                        DefaultKeySize = 128
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Hc256, new StreamCipherInformation {
                        Name = StreamCipher.Hc256.ToString(),
                        DisplayName = "HC-256",
                        AllowableNonceSizes = new[] { 128, 256 },
                        DefaultNonceSize = 256,
                        AllowableKeySizes = new[] { 128, 256 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Rabbit, new StreamCipherInformation {
                        Name = StreamCipher.Rabbit.ToString(),
                        DisplayName = "Rabbit",
                        AllowableNonceSizes = new[] { 64 },
                        DefaultNonceSize = 64,
                        AllowableKeySizes = new[] { 128 },
                        DefaultKeySize = 128
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Salsa20, new StreamCipherInformation {
                        Name = StreamCipher.Salsa20.ToString(),
                        DisplayName = "Salsa20",
                        AllowableNonceSizes = new[] { 64 },
                        DefaultNonceSize = 64,
                        AllowableKeySizes = new[] { 128, 256 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.ChaCha, new StreamCipherInformation {
                        Name = StreamCipher.ChaCha.ToString(),
                        DisplayName = "ChaCha",
                        AllowableNonceSizes = new[] { 64 },
                        DefaultNonceSize = 64,
                        AllowableKeySizes = new[] { 128, 256 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.XSalsa20, new StreamCipherInformation {
                        Name = StreamCipher.XSalsa20.ToString(),
                        DisplayName = "XSalsa20",
                        AllowableNonceSizes = new[] { 64, 128, 192 },
                        DefaultNonceSize = 192,
                        AllowableKeySizes = new[] { 80, 128, 256 },
                        DefaultKeySize = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Sosemanuk, new StreamCipherInformation {
                        Name = StreamCipher.Sosemanuk.ToString(),
                        DisplayName = "SOSEMANUK",
                        AllowableNonceSizes = new[] { 32, 48, 64, 80, 96, 112, 128 },
                        DefaultNonceSize = 128,
                        AllowableKeySizes = new[] { 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256 },
                        DefaultKeySize = 128
                    })
            });

            BlockCipherModeDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<BlockCipherMode, BlockCipherModeInformation>(
                    BlockCipherMode.Cbc, new BlockCipherModeInformation {
                        Name = BlockCipherMode.Cbc.ToString(),
                        DisplayName = "Ciphertext Block Chaining (CBC)",
                        PaddingRequirement = PaddingRequirement.Always,
                        AllowableBlockSizes = new[] { -1 },
                        NonceReusePolicy = NoncePolicy.RequireRandom
                    }),
                new KeyValuePair<BlockCipherMode, BlockCipherModeInformation>(
                    BlockCipherMode.Cfb, new BlockCipherModeInformation {
                        Name = BlockCipherMode.Cfb.ToString(),
                        DisplayName = "Cipher Feedback (CFB)",
                        PaddingRequirement = PaddingRequirement.None,
                        AllowableBlockSizes = new[] { -1 },
                        NonceReusePolicy = NoncePolicy.CounterAllowed
                    }),
                new KeyValuePair<BlockCipherMode, BlockCipherModeInformation>(
                    BlockCipherMode.Ctr, new BlockCipherModeInformation {
                        Name = BlockCipherMode.Ctr.ToString(),
                        DisplayName = "Counter / Segmented Integer Counter (CTR/SIC)",
                        PaddingRequirement = PaddingRequirement.None,
                        AllowableBlockSizes = new[] { -1 },
                        NonceReusePolicy = NoncePolicy.CounterAllowed
                    }),
                new KeyValuePair<BlockCipherMode, BlockCipherModeInformation>(
                    BlockCipherMode.Ofb, new BlockCipherModeInformation {
                        Name = BlockCipherMode.Ofb.ToString(),
                        DisplayName = "Output Feedback (OFB)",
                        PaddingRequirement = PaddingRequirement.None,
                        AllowableBlockSizes = new[] { -1 },
                        NonceReusePolicy = NoncePolicy.CounterAllowed
                    })
            });

            BlockCipherPaddingDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<BlockCipherPadding, BlockCipherPaddingInformation>(
                    BlockCipherPadding.Iso10126D2, new BlockCipherPaddingInformation {
                        Name = BlockCipherPadding.Iso10126D2.ToString(),
                        DisplayName = "ISO 10126-2"
                    }),
                new KeyValuePair<BlockCipherPadding, BlockCipherPaddingInformation>(
                    BlockCipherPadding.Iso7816D4, new BlockCipherPaddingInformation {
                        Name = BlockCipherPadding.Iso7816D4.ToString(),
                        DisplayName = "ISO/IEC 7816-4"
                    }),
                new KeyValuePair<BlockCipherPadding, BlockCipherPaddingInformation>(
                    BlockCipherPadding.Pkcs7, new BlockCipherPaddingInformation {
                        Name = BlockCipherPadding.Pkcs7.ToString(),
                        DisplayName = "PKCS 7"
                    }),
                new KeyValuePair<BlockCipherPadding, BlockCipherPaddingInformation>(
                    BlockCipherPadding.Tbc, new BlockCipherPaddingInformation {
                        Name = BlockCipherPadding.Tbc.ToString(),
                        DisplayName = "Trailing Bit Complement (TBC)"
                    }),
                new KeyValuePair<BlockCipherPadding, BlockCipherPaddingInformation>(
                    BlockCipherPadding.X923, new BlockCipherPaddingInformation {
                        Name = BlockCipherPadding.X923.ToString(),
                        DisplayName = "ANSI X.923"
                    })
            });
        }
    }
}
