#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.Contracts;
using Obscur.Core.Cryptography.Ciphers.Block;
using Obscur.Core.Cryptography.Ciphers.Block.Modes;
using Obscur.Core.Cryptography.Ciphers.Block.Padding;
using Obscur.Core.Cryptography.Ciphers.Block.Primitives;
using Obscur.Core.Cryptography.Ciphers.Stream;
using Obscur.Core.Cryptography.Ciphers.Stream.Primitives;

namespace Obscur.Core.Cryptography.Ciphers
{
    /// <summary>
    ///     Factory for cipher primitives.
    /// </summary>
    public static class CipherFactory
    {
        private static readonly IReadOnlyDictionary<BlockCipher, Func<int, BlockCipherBase>> EngineInstantiatorsBlock;
        private static readonly IReadOnlyDictionary<StreamCipher, Func<StreamCipherEngine>> EngineInstantiatorsStream;
        private static readonly IReadOnlyDictionary<BlockCipherMode, Func<BlockCipherBase, BlockCipherModeBase>> ModeInstantiatorsBlock;
        private static readonly IReadOnlyDictionary<BlockCipherPadding, Func<IBlockCipherPadding>> PaddingInstantiators;

        static CipherFactory()
        {
            /* ######################################## ENGINES ######################################## */
            // Block ciphers
            EngineInstantiatorsBlock = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Aes, blockSize => new AesEngine()),
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Blowfish, blockSize => new BlowfishEngine()),
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Camellia, blockSize => new CamelliaEngine()),
#if INCLUDE_IDEA
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Idea, blockSize => new IdeaEngine()),
#endif
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Noekeon, blockSize => new NoekeonEngine()),
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Rc6, blockSize => new Rc6Engine()),
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Serpent, blockSize => new SerpentEngine()),
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Threefish, blockSize => new ThreefishEngine(blockSize)),
                new KeyValuePair<BlockCipher, Func<int, BlockCipherBase>>(BlockCipher.Twofish, blockSize => new TwofishEngine())
            });
            // Stream ciphers
            EngineInstantiatorsStream = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.Hc128, () => new Hc128Engine()),
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.Hc256, () => new Hc256Engine()),
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.Rabbit, () => new RabbitEngine()),
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.Salsa20, () => new Salsa20Engine()),
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.XSalsa20, () => new XSalsa20Engine()),
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.ChaCha, () => new ChaChaEngine()),
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.Sosemanuk, () => new SosemanukEngine()),
                #if DEBUG
                new KeyValuePair<StreamCipher, Func<StreamCipherEngine>>(StreamCipher.None, () => new NullEngine())
                #endif
            });

            /* ######################################## BLOCK MODES ######################################## */
            ModeInstantiatorsBlock = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<BlockCipherMode, Func<BlockCipherBase, BlockCipherModeBase>>(BlockCipherMode.Cbc,
                    cipher => new CbcBlockCipher(cipher)),
                new KeyValuePair<BlockCipherMode, Func<BlockCipherBase, BlockCipherModeBase>>(BlockCipherMode.Cfb,
                    cipher => new CfbBlockCipher(cipher)),
                new KeyValuePair<BlockCipherMode, Func<BlockCipherBase, BlockCipherModeBase>>(BlockCipherMode.Ctr,
                    cipher => new CtrBlockCipher(cipher)),
                new KeyValuePair<BlockCipherMode, Func<BlockCipherBase, BlockCipherModeBase>>(BlockCipherMode.Ofb,
                    cipher => new OfbBlockCipher(cipher))
            });

            /* ######################################## PADDINGS ######################################## */
            PaddingInstantiators = ImmutableDictionary.CreateRange(new[] {
                new KeyValuePair<BlockCipherPadding, Func<IBlockCipherPadding>>(BlockCipherPadding.Iso10126D2, () => new Iso10126D2Padding()),
                new KeyValuePair<BlockCipherPadding, Func<IBlockCipherPadding>>(BlockCipherPadding.Iso7816D4, () => new Iso7816D4Padding()),
                new KeyValuePair<BlockCipherPadding, Func<IBlockCipherPadding>>(BlockCipherPadding.Pkcs7, () => new Pkcs7Padding()),
                new KeyValuePair<BlockCipherPadding, Func<IBlockCipherPadding>>(BlockCipherPadding.Tbc, () => new TbcPadding()),
                new KeyValuePair<BlockCipherPadding, Func<IBlockCipherPadding>>(BlockCipherPadding.X923, () => new X923Padding())
            });
        }

        /// <summary>
        ///     Instantiates and returns an implementation of the requested symmetric block cipher.
        /// </summary>
        /// <returns>A <see cref="BlockCipherBase" /> cipher object implementing the relevant cipher algorithm.</returns>
        public static BlockCipherBase CreateBlockCipher(BlockCipher cipherEnum, int? blockSize = null)
        {
            if (cipherEnum == BlockCipher.None) {
                throw new ArgumentException("Cipher set to None.", "cipherEnum",
                    new InvalidOperationException("Cannot instantiate null block cipher."));
            }
            if (blockSize == null) {
                blockSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSizeBits;
            }
            return EngineInstantiatorsBlock[cipherEnum](blockSize.Value);
        }

        /// <summary>
        ///     Implements a mode of operation on top of an existing block cipher.
        /// </summary>
        /// <param name="cipher">The block cipher to implement this mode of operation on top of.</param>
        /// <param name="modeEnum">The mode of operation to implement.</param>
        /// <returns>
        ///     A <see cref="BlockCipherBase" /> object implementing the relevant mode of operation,
        ///     overlaying the supplied symmetric block cipher.
        /// </returns>
        public static BlockCipherModeBase OverlayBlockCipherWithMode(BlockCipherBase cipher, BlockCipherMode modeEnum)
        {
            Contract.Requires<ArgumentNullException>(cipher != null);
            Contract.Requires(modeEnum != BlockCipherMode.None, "Cannot instantiate null mode of operation.");

            BlockCipherModeBase cipherMode = ModeInstantiatorsBlock[modeEnum](cipher);
            return cipherMode;
        }

        /// <summary>
        ///     Instantiates and returns an implementation of the requested padding mode.
        ///     Must be combined with a block cipher for operation. <seealso cref="BlockCipherWrapper" />
        /// </summary>
        /// <returns>
        ///     A <see cref="IBlockCipherPadding" /> object implementing the relevant padding scheme.
        /// </returns>
        public static IBlockCipherPadding CreatePadding(BlockCipherPadding paddingEnum)
        {
            Contract.Requires(paddingEnum != BlockCipherPadding.None, "Cannot instantiate null block cipher padding.");
            return PaddingInstantiators[paddingEnum]();
        }

        // Stream ciphers

        /// <summary>
        ///     Instantiates and returns an implementation of the requested symmetric stream cipher.
        /// </summary>
        /// <returns><see cref="StreamCipherEngine" /> object implementing the relevant cipher algorithm.</returns>
        public static StreamCipherEngine CreateStreamCipher(StreamCipher cipherEnum)
        {
#if !DEBUG
            if (cipherEnum == StreamCipher.None) {
                throw new ArgumentException("Cipher set to none.", "cipherEnum",
                    new InvalidOperationException("Cannot instantiate null stream cipher."));
            }
#endif
            return EngineInstantiatorsStream[cipherEnum]();
        }
    }
}
