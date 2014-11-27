using System.Collections.Generic;
using System.Collections.Immutable;
using Obscur.Core.Cryptography.Ciphers.Block;
using Obscur.Core.Cryptography.Ciphers.Information;
using Obscur.Core.Cryptography.Ciphers.Stream;

namespace Obscur.Core.Cryptography.Ciphers
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
                        AllowableBlockSizesBits = new[] { 128 },
                        DefaultBlockSizeBits = 128,
                        AllowableKeySizesBits = new[] { 128, 192, 256 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Blowfish, new BlockCipherInformation {
                        Name = BlockCipher.Blowfish.ToString(),
                        DisplayName = "Blowfish",
                        AllowableBlockSizesBits = new[] { 64 },
                        DefaultBlockSizeBits = 64,
                        AllowableKeySizesBits =
                            new[] { 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Camellia, new BlockCipherInformation {
                        Name = BlockCipher.Camellia.ToString(),
                        DisplayName = "Camellia",
                        AllowableBlockSizesBits = new[] { 128 },
                        DefaultBlockSizeBits = 128,
                        AllowableKeySizesBits = new[] { 128, 192, 256 },
                        DefaultKeySizeBits = 256
#if INCLUDE_IDEA
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Idea, new BlockCipherInformation {
                        Name = BlockCipher.Idea.ToString(),
                        DisplayName = "International Data Encryption Algorithm (IDEA)",
                        AllowableBlockSizesBits = new[] { 64 },
                        DefaultBlockSizeBits = 64,
                        AllowableKeySizesBits = new[] { 128 },
                        DefaultKeySizeBits = 128
#endif
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Noekeon, new BlockCipherInformation {
                        Name = BlockCipher.Noekeon.ToString(),
                        DisplayName = "NOEKEON",
                        AllowableBlockSizesBits = new[] { 128 },
                        DefaultBlockSizeBits = 128,
                        AllowableKeySizesBits = new[] { 128 },
                        DefaultKeySizeBits = 128
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Rc6, new BlockCipherInformation {
                        Name = BlockCipher.Rc6.ToString(),
                        DisplayName = "RC6",
                        AllowableBlockSizesBits = new[] { 128 },
                        DefaultBlockSizeBits = 128,
                        AllowableKeySizesBits = new[] { 128, 192, 256 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Serpent, new BlockCipherInformation {
                        Name = BlockCipher.Serpent.ToString(),
                        DisplayName = "Serpent",
                        AllowableBlockSizesBits = new[] { 128 },
                        DefaultBlockSizeBits = 128,
                        AllowableKeySizesBits = new[] { 128, 192, 256 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Threefish, new BlockCipherInformation {
                        Name = BlockCipher.Threefish.ToString(),
                        DisplayName = "Threefish",
                        AllowableBlockSizesBits = new[] { 256, 512, 1024 },
                        DefaultBlockSizeBits = 256,
                        AllowableKeySizesBits = new[] { 256, 512, 1024 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<BlockCipher, BlockCipherInformation>(
                    BlockCipher.Twofish, new BlockCipherInformation {
                        Name = BlockCipher.Twofish.ToString(),
                        DisplayName = "Twofish",
                        AllowableBlockSizesBits = new[] { 128 },
                        DefaultBlockSizeBits = 128,
                        AllowableKeySizesBits = new[] { 128, 192, 256 },
                        DefaultKeySizeBits = 256
                    })
            });

            StreamCipherDictionary = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Hc128, new StreamCipherInformation {
                        Name = StreamCipher.Hc128.ToString(),
                        DisplayName = "HC-128",
                        AllowableNonceSizesBits = new[] { 128 },
                        DefaultNonceSizeBits = 128,
                        AllowableKeySizesBits = new[] { 128 },
                        DefaultKeySizeBits = 128
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Hc256, new StreamCipherInformation {
                        Name = StreamCipher.Hc256.ToString(),
                        DisplayName = "HC-256",
                        AllowableNonceSizesBits = new[] { 128, 256 },
                        DefaultNonceSizeBits = 256,
                        AllowableKeySizesBits = new[] { 128, 256 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Rabbit, new StreamCipherInformation {
                        Name = StreamCipher.Rabbit.ToString(),
                        DisplayName = "Rabbit",
                        AllowableNonceSizesBits = new[] { 64 },
                        DefaultNonceSizeBits = 64,
                        AllowableKeySizesBits = new[] { 128 },
                        DefaultKeySizeBits = 128
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Salsa20, new StreamCipherInformation {
                        Name = StreamCipher.Salsa20.ToString(),
                        DisplayName = "Salsa20",
                        AllowableNonceSizesBits = new[] { 64 },
                        DefaultNonceSizeBits = 64,
                        AllowableKeySizesBits = new[] { 128, 256 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.ChaCha, new StreamCipherInformation {
                        Name = StreamCipher.ChaCha.ToString(),
                        DisplayName = "ChaCha",
                        AllowableNonceSizesBits = new[] { 64 },
                        DefaultNonceSizeBits = 64,
                        AllowableKeySizesBits = new[] { 128, 256 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.XSalsa20, new StreamCipherInformation {
                        Name = StreamCipher.XSalsa20.ToString(),
                        DisplayName = "XSalsa20",
                        AllowableNonceSizesBits = new[] { 64, 128, 192 },
                        DefaultNonceSizeBits = 192,
                        AllowableKeySizesBits = new[] { 80, 128, 256 },
                        DefaultKeySizeBits = 256
                    }),
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.Sosemanuk, new StreamCipherInformation {
                        Name = StreamCipher.Sosemanuk.ToString(),
                        DisplayName = "SOSEMANUK",
                        AllowableNonceSizesBits = new[] { 32, 48, 64, 80, 96, 112, 128 },
                        DefaultNonceSizeBits = 128,
                        AllowableKeySizesBits = new[] { 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256 },
                        DefaultKeySizeBits = 128
                    })
                // Null cipher - not actually a cipher - use ONLY for testing!
#if DEBUG
                ,
                new KeyValuePair<StreamCipher, StreamCipherInformation>(
                    StreamCipher.None, new StreamCipherInformation {
                        Name = StreamCipher.None.ToString(),
                        DisplayName = "Null Test Engine (not a cipher)",
                        AllowableNonceSizesBits = new[] { 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256 },
                        DefaultNonceSizeBits = 64,
                        AllowableKeySizesBits = new[] { 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256 },
                        DefaultKeySizeBits = 64
                    })
#endif
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
