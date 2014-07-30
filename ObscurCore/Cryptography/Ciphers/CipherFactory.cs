//
//  Copyright 2014  Matthew Ducker
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
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Modes;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Block.Primitives;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;

namespace ObscurCore.Cryptography.Ciphers
{
    /// <summary>
    ///     Factory for cipher primitives.
    /// </summary>
    public static class CipherFactory
    {
        private static readonly IDictionary<BlockCipher, Func<int, BlockCipherBase>> EngineInstantiatorsBlock;

        private static readonly IDictionary<StreamCipher, Func<StreamCipherEngine>> EngineInstantiatorsStream;

        private static readonly IDictionary<BlockCipherMode, Func<BlockCipherBase, BlockCipherModeBase>> ModeInstantiatorsBlock;

        private static readonly IDictionary<BlockCipherPadding, Func<IBlockCipherPadding>> PaddingInstantiators;

        static CipherFactory()
        {
            // ######################################## ENGINES ########################################
            EngineInstantiatorsBlock = new Dictionary<BlockCipher, Func<int, BlockCipherBase>> {
                { BlockCipher.Aes, blockSize => new AesEngine() },
                { BlockCipher.Blowfish, blockSize => new BlowfishEngine() },
                { BlockCipher.Camellia, blockSize => new CamelliaEngine() },
#if INCLUDE_IDEA
                { BlockCipher.Idea, blockSize => new IdeaEngine() },
#endif
                { BlockCipher.Noekeon, blockSize => new NoekeonEngine() },
                { BlockCipher.Rc6, blockSize => new Rc6Engine() },
                { BlockCipher.Serpent, blockSize => new SerpentEngine() },
                { BlockCipher.Threefish, blockSize => new ThreefishEngine(blockSize) },
                { BlockCipher.Twofish, blockSize => new TwofishEngine() }
            };

            EngineInstantiatorsStream = new Dictionary<StreamCipher, Func<StreamCipherEngine>> {
                { StreamCipher.Hc128, () => new Hc128Engine() },
                { StreamCipher.Hc256, () => new Hc256Engine() },
                { StreamCipher.Rabbit, () => new RabbitEngine() },
                { StreamCipher.Salsa20, () => new Salsa20Engine() },
                { StreamCipher.ChaCha, () => new ChaChaEngine() },
                { StreamCipher.XSalsa20, () => new XSalsa20Engine() },
                { StreamCipher.Sosemanuk, () => new SosemanukEngine() }
            };

            // ######################################## BLOCK MODES ########################################
            ModeInstantiatorsBlock = new Dictionary<BlockCipherMode, Func<BlockCipherBase, BlockCipherModeBase>> {
                { BlockCipherMode.Cbc, cipher => new CbcBlockCipher(cipher) },
                { BlockCipherMode.Cfb, cipher => new CfbBlockCipher(cipher) },
                { BlockCipherMode.Ctr, cipher => new CtrBlockCipher(cipher) },
                { BlockCipherMode.Ofb, cipher => new OfbBlockCipher(cipher) }
            };

            // ######################################## PADDINGS ########################################
            PaddingInstantiators = new Dictionary<BlockCipherPadding, Func<IBlockCipherPadding>> {
                { BlockCipherPadding.Iso10126D2, () => new Iso10126D2Padding() },
                { BlockCipherPadding.Iso7816D4, () => new Iso7816D4Padding() },
                { BlockCipherPadding.Pkcs7, () => new Pkcs7Padding() },
                { BlockCipherPadding.Tbc, () => new TbcPadding() },
                { BlockCipherPadding.X923, () => new X923Padding() }
            };
        }

        /// <summary>
        ///     Instantiates and returns an implementation of the requested symmetric block cipher.
        /// </summary>
        /// <returns>A <see cref="BlockCipherBase"/> cipher object implementing the relevant cipher algorithm.</returns>
        public static BlockCipherBase CreateBlockCipher(BlockCipher cipherEnum, int? blockSize = null)
        {
            if (cipherEnum == BlockCipher.None) {
                throw new ArgumentException("Cipher set to None.", "cipherEnum",
                    new InvalidOperationException("Cannot instantiate null block cipher."));
            }
            if (blockSize == null) {
                blockSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize;
            }
            return EngineInstantiatorsBlock[cipherEnum](blockSize.Value);
        }

        /// <summary>
        ///     Instantiates and returns an implementation of the requested symmetric block cipher.
        /// </summary>
        /// <returns>A <see cref="BlockCipherBase"/> cipher object implementing the relevant cipher algorithm.</returns>
        public static BlockCipherBase CreateBlockCipher(string cipherName, int? blockSize = null)
        {
            return CreateBlockCipher(cipherName.ToEnum<BlockCipher>(), blockSize);
        }

        /// <summary>
        ///     Implements a mode of operation on top of an existing block cipher.
        /// </summary>
        /// <param name="cipher">The block cipher to implement this mode of operation on top of.</param>
        /// <param name="modeEnum">The mode of operation to implement.</param>
        /// <returns>
        ///     A <see cref="BlockCipherBase"/> object implementing the relevant mode of operation,
        ///     overlaying the supplied symmetric block cipher.
        /// </returns>
        public static BlockCipherModeBase OverlayBlockCipherWithMode(BlockCipherBase cipher, BlockCipherMode modeEnum)
        {
            if (cipher == null) {
                throw new ArgumentNullException();
            }
            if (modeEnum == BlockCipherMode.None) {
                throw new ArgumentException("Mode set to none.", "modeEnum",
                    new InvalidOperationException("Cannot instantiate null mode of operation."));
            }
            BlockCipherModeBase cipherMode = ModeInstantiatorsBlock[modeEnum](cipher);
            return cipherMode;
        }

        public static BlockCipherModeBase OverlayBlockCipherWithMode(BlockCipherBase cipher, string modeName)
        {
            return OverlayBlockCipherWithMode(cipher, modeName.ToEnum<BlockCipherMode>());
        }

        /// <summary>
        ///     Instantiates and returns an implementation of the requested padding mode.
        ///     Must be combined with a block cipher for operation. <seealso cref="BlockCipherWrapper"/>
        /// </summary>
        /// <returns>
        ///     A <see cref="IBlockCipherPadding"/> object implementing the relevant padding scheme.
        /// </returns>
        public static IBlockCipherPadding CreatePadding(BlockCipherPadding paddingEnum)
        {
            if (paddingEnum == BlockCipherPadding.None) {
                throw new ArgumentException("Padding set to None.", "paddingEnum",
                    new InvalidOperationException("Cannot instantiate null block cipher padding."));
            }
            return PaddingInstantiators[paddingEnum]();
        }

        public static IBlockCipherPadding CreatePadding(string paddingName)
        {
            return CreatePadding(paddingName.ToEnum<BlockCipherPadding>());
        }

        // Stream ciphers

        /// <summary>
        ///     Instantiates and returns an implementation of the requested symmetric stream cipher.
        /// </summary>
        /// <returns>A <see cref="StreamCipherEngine"/> cipher object implementing the relevant cipher algorithm.</returns>
        public static StreamCipherEngine CreateStreamCipher(StreamCipher cipherEnum)
        {
            if (cipherEnum == StreamCipher.None) {
                throw new ArgumentException("Cipher set to none.", "cipherEnum",
                    new InvalidOperationException("Cannot instantiate null stream cipher."));
            }
            return EngineInstantiatorsStream[cipherEnum]();
        }

        public static StreamCipherEngine CreateStreamCipher(string cipherName)
        {
            return EngineInstantiatorsStream[cipherName.ToEnum<StreamCipher>()]();
        }
    }
}
