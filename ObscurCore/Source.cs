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
using System.Text;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Modes;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Block.Primitives;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore
{
    /// <summary>
    /// Creation/factory class. Instantiates and initialises core objects.
    /// </summary>
    public static class Source
    {
        private readonly static IDictionary<SymmetricBlockCipher, Func<int, IBlockCipher>> EngineInstantiatorsBlock =
            new Dictionary<SymmetricBlockCipher, Func<int, IBlockCipher>>();
        private readonly static IDictionary<SymmetricStreamCipher, Func<IStreamCipher>> EngineInstantiatorsStream =
            new Dictionary<SymmetricStreamCipher, Func<IStreamCipher>>();

        private readonly static IDictionary<BlockCipherMode, Func<IBlockCipher, IBlockCipher>> ModeInstantiatorsBlock =
			new Dictionary<BlockCipherMode, Func<IBlockCipher, IBlockCipher>>();

        private readonly static IDictionary<BlockCipherPadding, Func<IBlockCipherPadding>> PaddingInstantiators =
            new Dictionary<BlockCipherPadding, Func<IBlockCipherPadding>>();

        private readonly static IDictionary<KeyDerivationFunction, Func<int, byte[], IKdfFunction>> KdfInstantiators =
			new Dictionary<KeyDerivationFunction, Func<int, byte[], IKdfFunction>>();
		
		private readonly static IDictionary<KeyDerivationFunction, Func<byte[], byte[], int, byte[], byte[]>> KdfStatics =
			new Dictionary<KeyDerivationFunction, Func<byte[], byte[], int, byte[], byte[]>>();

        private readonly static IDictionary<CsPseudorandomNumberGenerator, Func<byte[], Csprng>> PrngInstantiators =
			new Dictionary<CsPseudorandomNumberGenerator, Func<byte[], Csprng>>();

        private readonly static IDictionary<HashFunction, Func<IDigest>> DigestInstantiators =
			new Dictionary<HashFunction, Func<IDigest>>();

        private readonly static IDictionary<MacFunction, Func<IMac>> MacInstantiators =
			new Dictionary<MacFunction, Func<IMac>>();

        // Packaging related

		private readonly static IDictionary<PayloadLayoutScheme, Func<bool, Stream, List<PayloadItem>, IReadOnlyDictionary<Guid, byte[]>,
			IPayloadConfiguration, PayloadMux>> PayloadLayoutModuleInstantiators = new Dictionary<PayloadLayoutScheme, 
		Func<bool, Stream, List<PayloadItem>, IReadOnlyDictionary<Guid, byte[]>, IPayloadConfiguration, PayloadMux>>();

        static Source() {
            // ######################################## ENGINES ########################################
            // Block engines
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Aes, blockSize => new AesFastEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Blowfish, blockSize => new BlowfishEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Cast5, blockSize => new Cast5Engine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Cast6, blockSize => new Cast6Engine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Camellia, blockSize => new CamelliaEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Idea, blockSize => new IdeaEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Noekeon, blockSize => new NoekeonEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Rc6, blockSize => new Rc6Engine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Serpent, blockSize => new SerpentEngine());
			EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Threefish, blockSize => new ThreefishEngine(blockSize));
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Twofish, blockSize => new TwofishEngine());

            // Stream engines
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Hc128, () => new Hc128Engine());
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Hc256, () => new Hc256Engine());
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Rabbit, () => new RabbitEngine());
#if INCLUDE_RC4
			EngineInstantiatorsStream.Add(SymmetricStreamCipher.Rc4, () => new Rc4Engine());
#endif
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Salsa20, () => new Salsa20Engine());
			EngineInstantiatorsStream.Add(SymmetricStreamCipher.ChaCha, () => new ChaChaEngine());
			EngineInstantiatorsStream.Add(SymmetricStreamCipher.XSalsa20, () => new XSalsa20Engine());
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Sosemanuk, () => new SosemanukEngine());

            // ######################################## BLOCK MODES ########################################
            ModeInstantiatorsBlock.Add(BlockCipherMode.Cbc, (cipher) => new CbcBlockCipher(cipher));
            ModeInstantiatorsBlock.Add(BlockCipherMode.Cfb, (cipher) => new CfbBlockCipher(cipher));
            ModeInstantiatorsBlock.Add(BlockCipherMode.Ctr, (cipher) => new CtrBlockCipher(cipher));
            ModeInstantiatorsBlock.Add(BlockCipherMode.Ofb, (cipher) => new OfbBlockCipher(cipher));

            // ######################################## PADDING ########################################

            PaddingInstantiators.Add(BlockCipherPadding.Iso10126D2, () => new Iso10126D2Padding());
            PaddingInstantiators.Add(BlockCipherPadding.Iso7816D4, () => new Iso7816D4Padding());
			PaddingInstantiators.Add(BlockCipherPadding.Pkcs7, () => new Pkcs7Padding());
			PaddingInstantiators.Add(BlockCipherPadding.Tbc, () => new TbcPadding());
			PaddingInstantiators.Add(BlockCipherPadding.X923, () => new X923Padding());

            // ######################################## KEY DERIVATION ########################################

            KdfInstantiators.Add(KeyDerivationFunction.Pbkdf2, (outputSize, config) => new Pbkdf2Module(outputSize, config));
			KdfInstantiators.Add(KeyDerivationFunction.Scrypt, (outputSize, config) => new ScryptModule(outputSize, config));
			
			KdfStatics.Add(KeyDerivationFunction.Pbkdf2, Pbkdf2Module.DeriveKeyWithConfig);
			KdfStatics.Add(KeyDerivationFunction.Scrypt, ScryptModule.DeriveKeyWithConfig);

            // ######################################## PRNG ########################################

            PrngInstantiators.Add(CsPseudorandomNumberGenerator.Salsa20, config => new Salsa20Generator(config));
			PrngInstantiators.Add(CsPseudorandomNumberGenerator.Sosemanuk, config => new SosemanukGenerator(config));

            // ######################################## HASHING ########################################

            DigestInstantiators.Add(HashFunction.Blake2B256, () => new Blake2BDigest(256, true));
			DigestInstantiators.Add(HashFunction.Blake2B384, () => new Blake2BDigest(384, true));
			DigestInstantiators.Add(HashFunction.Blake2B512, () => new Blake2BDigest(512, true));
			DigestInstantiators.Add(HashFunction.Keccak224, () => new KeccakDigest(224, true));
			DigestInstantiators.Add(HashFunction.Keccak256, () => new KeccakDigest(256, true));
			DigestInstantiators.Add(HashFunction.Keccak384, () => new KeccakDigest(384, true));
			DigestInstantiators.Add(HashFunction.Keccak512, () => new KeccakDigest(512, true));
#if INCLUDE_SHA1
            DigestInstantiators.Add(HashFunction.Sha1, () => new Sha1Digest());
#endif
            DigestInstantiators.Add(HashFunction.Sha256, () => new Sha256Digest());
            DigestInstantiators.Add(HashFunction.Sha512, () => new Sha512Digest());
            DigestInstantiators.Add(HashFunction.Ripemd160, () => new RipeMD160Digest());
            DigestInstantiators.Add(HashFunction.Tiger, () => new TigerDigest());

            // ######################################## MAC ########################################

            MacInstantiators.Add(MacFunction.Blake2B256, () => new Blake2BMac(256, true));
			MacInstantiators.Add(MacFunction.Blake2B384, () => new Blake2BMac(384, true));
			MacInstantiators.Add(MacFunction.Blake2B512, () => new Blake2BMac(512, true));

			MacInstantiators.Add(MacFunction.Keccak224, () => new KeccakMac(224, true));
			MacInstantiators.Add(MacFunction.Keccak256, () => new KeccakMac(256, true));
			MacInstantiators.Add(MacFunction.Keccak384, () => new KeccakMac(384, true));
			MacInstantiators.Add(MacFunction.Keccak512, () => new KeccakMac(512, true));


            // ######################################## PACKAGING ########################################

			PayloadLayoutModuleInstantiators.Add (PayloadLayoutScheme.Simple, (writing, multiplexedStream, payloadItems, itemPreKeys, config) => 
				new SimplePayloadMux (writing, multiplexedStream, payloadItems, itemPreKeys, config));
			PayloadLayoutModuleInstantiators.Add(PayloadLayoutScheme.Frameshift, (writing, multiplexedStream, payloadItems, itemPreKeys, config) => 
				new FrameshiftPayloadMux(writing, multiplexedStream, payloadItems, itemPreKeys, config));
			PayloadLayoutModuleInstantiators.Add(PayloadLayoutScheme.Fabric, (writing, multiplexedStream, payloadItems, itemPreKeys, config) => 
				new FabricPayloadMux(writing, multiplexedStream, payloadItems, itemPreKeys, config));

            // ######################################## INIT END ########################################
        }

        // Block ciphers

        /// <summary>
        /// Instantiates and returns an implementation of the requested symmetric block cipher.
        /// </summary>
        /// <returns>An IBlockCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IBlockCipher CreateBlockCipher (SymmetricBlockCipher cipherEnum, int? blockSize = null) {
            if (blockSize == null) blockSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize;
            return EngineInstantiatorsBlock[cipherEnum](blockSize.Value);
        }

        public static IBlockCipher CreateBlockCipher (string cipherName, int? blockSize = null) {
            return CreateBlockCipher(cipherName.ToEnum<SymmetricBlockCipher>(), blockSize);
        }

        /// <summary>
        /// Implements a mode of operation on top of an existing block cipher. 
        /// Attention: CTS (CTS_CBC) mode invocations require further manipulation prior to use.
        /// </summary>
        /// <param name="cipher">The block cipher to implement this mode of operation on top of.</param>
        /// <param name="modeEnum">The mode of operation to implement.</param>
        /// <param name="size">Where applicable, the size parameter required for some modes of operation.</param>
        /// <returns>
        /// IBlockCipher object implementing the relevant mode of operation, 
        /// overlaying the supplied symmetric block cipher.
        /// </returns>
        public static IBlockCipher OverlayBlockCipherWithMode (IBlockCipher cipher, BlockCipherMode modeEnum) {
            if (cipher == null) {
                throw new ArgumentNullException();
            }
			var cipherMode = ModeInstantiatorsBlock[modeEnum](cipher);
            return cipherMode;
        }

        public static IBlockCipher OverlayBlockCipherWithMode (IBlockCipher cipher, string modeName) {
            return OverlayBlockCipherWithMode(cipher, modeName.ToEnum<BlockCipherMode>());
        }

        /// <summary>
        /// Instantiates and returns an implementation of the requested padding mode. 
        /// Must be combined with a block cipher for operation.
        /// </summary>
        /// <returns>
        /// An IBlockCipherPadding cipher object implementing the relevant padding scheme.
        /// </returns>
        public static IBlockCipherPadding CreatePadding (BlockCipherPadding paddingEnum) {
            return PaddingInstantiators[paddingEnum]();
        }

        public static IBlockCipherPadding CreatePadding (string paddingName) {
            return CreatePadding(paddingName.ToEnum<BlockCipherPadding>());
        }

        // Stream ciphers

        /// <summary>
        /// Instantiates and returns a symmetric stream cipher of the algorithm type that the instance this method was called from describes.
        /// </summary>
        /// <returns>An IStreamCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IStreamCipher CreateStreamCipher (SymmetricStreamCipher cipherEnum) {
            return EngineInstantiatorsStream[cipherEnum]();
        }

        public static IStreamCipher CreateStreamCipher (string cipherName) {
            return EngineInstantiatorsStream[cipherName.ToEnum<SymmetricStreamCipher>()]();
        }
        
        // Authentication-related

		/// <summary>
		/// Instantiates and returns a hash/digest primitive.
		/// </summary>
		/// <param name="hashEnum">Hash/digest function to instantiate.</param>
		/// <returns>
		/// An digest object deriving from IDigest.
		/// </returns>
		public static IDigest CreateHashPrimitive (HashFunction hashEnum) {
			return DigestInstantiators[hashEnum]();
		}

		public static IDigest CreateHashPrimitive(string hashName) {
			return CreateHashPrimitive(hashName.ToEnum<HashFunction>());
		}

		/// <summary>
		/// Instantiates and initialises a Message Authentication Code (MAC) primitive.
		/// </summary>
		/// <param name="macEnum">MAC function to instantiate.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
		/// <param name="config">Configuration for the function, where applicable. For example,
		/// CMAC and HMAC use cipher and hash function names, repectively, encoded as UTF-8.</param>
		/// <returns>
		/// An MAC object deriving from IMac.
		/// </returns>
		public static IMac CreateMacPrimitive (MacFunction macEnum, byte[] key, byte[] salt = null, 
			byte[] config = null, byte[] nonce = null) 
		{
			IMac macObj;
			if (macEnum == MacFunction.Hmac) {
				if (config == null)
					throw new ArgumentException ("No hash function specified (encoded as UTF-8 bytes).", "config");
				return macObj = CreateHmacPrimitive (Encoding.UTF8.GetString (config).ToEnum<HashFunction> (), key, salt);
			} else if (macEnum == MacFunction.Cmac) {
				if (config == null)
					throw new ArgumentException ("No block cipher specified (encoded as UTF-8 bytes).", "config");
				macObj = CreateCmacPrimitive (Encoding.UTF8.GetString (config).ToEnum<SymmetricBlockCipher> (), key, salt);
			} else if (macEnum == MacFunction.Poly1305) {
				if (config != null && nonce == null)
					throw new ArgumentException ("No nonce/IV supplied for the block cipher.", "nonce");
				macObj = CreatePoly1305Primitive (Encoding.UTF8.GetString (config).ToEnum<SymmetricBlockCipher> (), key, nonce, salt);
			} else {
				macObj = MacInstantiators[macEnum]();
				macObj.Init (key);
				if (salt.IsNullOrZeroLength() == false) 
					macObj.BlockUpdate(salt, 0, salt.Length);
			}

			return macObj;
		}

		public static IMac CreateMacPrimitive(string macName, byte[] key, byte[] salt = null, byte[] config = null, byte[] nonce = null) {
			return CreateMacPrimitive(macName.ToEnum<MacFunction>(), key, salt, config, nonce);
		}

		/// <summary>
		/// Creates a CMAC primitive using a symmetric block cipher primitive configured with default block size. 
		/// Default block sizes (and so, output sizes) can be found by querying Athena.
		/// </summary>
		/// <param name="cipherEnum">Cipher primitive to use as the basis for the CMAC construction.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
		/// <returns>Pre-initialised CMAC primitive.</returns>
		public static IMac CreateCmacPrimitive(SymmetricBlockCipher cipherEnum, byte[] key, byte[] salt = null) {
			var defaultBlockSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize;
			if(defaultBlockSize != 64 && defaultBlockSize != 128) {
				throw new NotSupportedException ("CMAC/OMAC1 only supports ciphers with 64 / 128 bit block sizes.");
			}
			var macObj = new CMac (CreateBlockCipher (cipherEnum, null));
			macObj.Init (key);
			if(salt.IsNullOrZeroLength() == false) 
				macObj.BlockUpdate(salt, 0, salt.Length);

			return macObj;
		}

        /// <summary>
		/// Creates a HMAC primitive using a hash/digest primitive.
		/// </summary>
		/// <param name="hashEnum">Hash/digest primitive to use as the basis for the HMAC construction.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
		/// <returns>Pre-initialised HMAC primitive.</returns>
		public static IMac CreateHmacPrimitive(HashFunction hashEnum, byte[] key, byte[] salt = null) {
			var macObj = new HMac (DigestInstantiators [hashEnum]());
			macObj.Init (key);
			if(salt.IsNullOrZeroLength() == false) 
				macObj.BlockUpdate(salt, 0, salt.Length);

			return macObj;
		}

		/// <summary>
		/// Creates a Poly1305 primitive using a symmetric block cipher primitive 
		/// (cipher must have a block size of 128 bits).
		/// </summary>
		/// <param name="cipherEnum">Cipher primitive to use as the basis for the Poly1305 construction.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="iv">Initialisation vector/nonce. Required.</param>
		/// <returns>Pre-initialised Poly1305 primitive.</returns>
		public static IMac CreatePoly1305Primitive(SymmetricBlockCipher cipherEnum, byte[] key, byte[] nonce, byte[] salt = null) {
			if(Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize != 128) {
				throw new NotSupportedException ();
			}

			var macObj = new Poly1305Mac (CreateBlockCipher (cipherEnum));
			macObj.Init (key, nonce);

			return macObj;
		}

        /// <summary>
        /// Derives a working key with the KDF module.
        /// </summary>
        /// <returns>The working key.</returns>
        /// <param name="kdfEnum">Key derivation function to use.</param>
        /// <param name="key">Pre-key to use as input material.</param>
        /// <param name="salt">Salt to use in derivation to increase entropy.</param>
		/// <param name="outputSize">Output key size in bytes.</param>
        /// <param name="config">Serialised configuration of the KDF.</param>
        public static byte[] DeriveKeyWithKdf (KeyDerivationFunction kdfEnum, byte[] key, byte[] salt, int outputSize, byte[] config) {
			return KdfStatics[kdfEnum](key, salt, outputSize, config);
		}
		
		public static IKdfFunction CreateKdf(KeyDerivationFunction kdfEnum, int outputSize, byte[] config) {
			return KdfInstantiators[kdfEnum](outputSize, config);
		}

        public static IKdfFunction CreateKdf(string kdfName, int outputSize, byte[] config) {
            return CreateKdf(kdfName.ToEnum<KeyDerivationFunction>(), outputSize, config);
        }

        /// <summary>
        /// Instantiates and returns a CSPRNG implementing a generator function.
        /// </summary>
        /// <param name="csprngEnum">CSPRNG function to use.</param>
        /// <param name="config">Serialised configuration of the CSPRNG.</param>
        /// <returns>
        /// An CSPRNG object deriving from CSPRNG.
        /// </returns>
        public static Csprng CreateCsprng (CsPseudorandomNumberGenerator csprngEnum, byte[] config) {
			return PrngInstantiators[csprngEnum](config);
		}

        public static Csprng CreateCsprng (string csprngName, byte[] config) {
            return CreateCsprng(csprngName.ToEnum<CsPseudorandomNumberGenerator>(), config);
        }

        public static StreamCipherCsprngConfiguration CreateStreamCipherCsprngConfiguration
            (CsPseudorandomNumberGenerator cipherEnum)
        {
            return StreamCsprng.CreateRandomConfiguration(cipherEnum);
        }

        public static ECDomainParameters GetEcDomainParameters(BrainpoolEllipticCurve curveEnum) {
            if (curveEnum == BrainpoolEllipticCurve.None) {
                throw new ArgumentException();
            }
            return GetEcDomainParameters(curveEnum.ToString());
        }

        public static ECDomainParameters GetEcDomainParameters(Sec2EllipticCurve curveEnum) {
            if (curveEnum == Sec2EllipticCurve.None) {
                throw new ArgumentException();
            }
            return GetEcDomainParameters(curveEnum.ToString());
        }

        public static ECDomainParameters GetEcDomainParameters(string name) {
			if (!NamedEllipticCurves.Curves.ContainsKey(name)) {
                throw new NotSupportedException("Named curve is unknown or unsupported.");
            }
			return NamedEllipticCurves.Curves[name].GetParameters();
        }


        // Packaging related

        /// <summary>
        /// Instantiates and returns a payload I/O module implementing the mode of operation that the
        /// instance this method was called from describes.
        /// </summary>
        /// <param name="schemeEnum">Payload layout scheme to choose the correspknding multiplexer.</param>
        /// <param name="writing">Whether the multiplexer will be multiplexing or demultiplexing.</param>
        /// <param name="multiplexedStream">Stream to multiplex/demultiplex to/from.</param>
        /// <param name="streams">Streams to multiplex/demultiplex to/from.</param>
        /// <param name="transforms">Transforms to apply to the payload items (e.g. encryption).</param>
        /// <param name="config">Configuration of the layout module/multiplexer.</param>
        /// <returns>
        /// An module object deriving from PayloadMultiplexer.
        /// </returns>
		public static PayloadMux CreatePayloadMultiplexer (PayloadLayoutScheme schemeEnum, bool writing, 
			Stream multiplexedStream, List<PayloadItem> payloadItems, IReadOnlyDictionary<Guid, byte[]> itemPreKeys, 
			IPayloadConfiguration config)
		{
			return PayloadLayoutModuleInstantiators[schemeEnum](writing, multiplexedStream, payloadItems, itemPreKeys, config);
		}
    }
}
