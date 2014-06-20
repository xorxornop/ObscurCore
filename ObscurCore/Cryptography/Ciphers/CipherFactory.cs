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
    public static class CipherFactory
    {
        private static readonly IDictionary<BlockCipher, Func<int, IBlockCipher>> EngineInstantiatorsBlock;

        private static readonly IDictionary<StreamCipher, Func<IStreamCipher>> EngineInstantiatorsStream;

        private static readonly IDictionary<BlockCipherMode, Func<IBlockCipher, IBlockCipher>> ModeInstantiatorsBlock;

        private static readonly IDictionary<BlockCipherPadding, Func<IBlockCipherPadding>> PaddingInstantiators;

        static CipherFactory()
        {
            // ######################################## ENGINES ########################################
            EngineInstantiatorsBlock = new Dictionary<BlockCipher, Func<int, IBlockCipher>> {
                { BlockCipher.Aes, blockSize => new AesFastEngine() },
                { BlockCipher.Blowfish, blockSize => new BlowfishEngine() },
#if INCLUDE_CAST5AND6
                { BlockCipher.Cast5, blockSize => new Cast5Engine() },
                { BlockCipher.Cast6, blockSize => new Cast6Engine() },
#endif
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

            EngineInstantiatorsStream = new Dictionary<StreamCipher, Func<IStreamCipher>> {
                { StreamCipher.Hc128, () => new Hc128Engine() },
                { StreamCipher.Hc256, () => new Hc256Engine() },
                { StreamCipher.Rabbit, () => new RabbitEngine() },
#if INCLUDE_RC4
                { StreamCipher.Rc4, () => new Rc4Engine() },
#endif
                { StreamCipher.Salsa20, () => new Salsa20Engine() },
                { StreamCipher.ChaCha, () => new ChaChaEngine() },
                { StreamCipher.XSalsa20, () => new XSalsa20Engine() },
                { StreamCipher.Sosemanuk, () => new SosemanukEngine() }
            };

            // ######################################## BLOCK MODES ########################################
            ModeInstantiatorsBlock = new Dictionary<BlockCipherMode, Func<IBlockCipher, IBlockCipher>> {
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
        /// <returns>An IBlockCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IBlockCipher CreateBlockCipher(BlockCipher cipherEnum, int? blockSize = null)
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

        public static IBlockCipher CreateBlockCipher(string cipherName, int? blockSize = null)
        {
            return CreateBlockCipher(cipherName.ToEnum<BlockCipher>(), blockSize);
        }

        /// <summary>
        ///     Implements a mode of operation on top of an existing block cipher.
        /// </summary>
        /// <param name="cipher">The block cipher to implement this mode of operation on top of.</param>
        /// <param name="modeEnum">The mode of operation to implement.</param>
        /// <returns>
        ///     IBlockCipher object implementing the relevant mode of operation,
        ///     overlaying the supplied symmetric block cipher.
        /// </returns>
        public static IBlockCipher OverlayBlockCipherWithMode(IBlockCipher cipher, BlockCipherMode modeEnum)
        {
            if (cipher == null) {
                throw new ArgumentNullException();
            }
            if (modeEnum == BlockCipherMode.None) {
                throw new ArgumentException("Mode set to none.", "modeEnum",
                    new InvalidOperationException("Cannot instantiate null mode of operation."));
            }
            IBlockCipher cipherMode = ModeInstantiatorsBlock[modeEnum](cipher);
            return cipherMode;
        }

        public static IBlockCipher OverlayBlockCipherWithMode(IBlockCipher cipher, string modeName)
        {
            return OverlayBlockCipherWithMode(cipher, modeName.ToEnum<BlockCipherMode>());
        }

        /// <summary>
        ///     Instantiates and returns an implementation of the requested padding mode.
        ///     Must be combined with a block cipher for operation.
        /// </summary>
        /// <returns>
        ///     An IBlockCipherPadding cipher object implementing the relevant padding scheme.
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
        ///     Instantiates and returns a symmetric stream cipher of the algorithm type that the instance this method was called
        ///     from describes.
        /// </summary>
        /// <returns>An IStreamCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IStreamCipher CreateStreamCipher(StreamCipher cipherEnum)
        {
            if (cipherEnum == StreamCipher.None) {
                throw new ArgumentException("Cipher set to none.", "cipherEnum",
                    new InvalidOperationException("Cannot instantiate null stream cipher."));
            }
            return EngineInstantiatorsStream[cipherEnum]();
        }

        public static IStreamCipher CreateStreamCipher(string cipherName)
        {
            return EngineInstantiatorsStream[cipherName.ToEnum<StreamCipher>()]();
        }
    }
}
