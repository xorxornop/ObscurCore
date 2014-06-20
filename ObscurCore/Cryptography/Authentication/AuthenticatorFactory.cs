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
using System.Text;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;

namespace ObscurCore.Cryptography.Authentication
{
    public static class AuthenticatorFactory
    {
        private static readonly IDictionary<HashFunction, Func<IDigest>> DigestInstantiators;

        private static readonly IDictionary<MacFunction, Func<IMac>> MacInstantiators;

        static AuthenticatorFactory()
        {
            // ######################################## HASH FUNCTIONS ########################################
            DigestInstantiators = new Dictionary<HashFunction, Func<IDigest>> {
                { HashFunction.Blake2B256, () => new Blake2BDigest(256, true) },
                { HashFunction.Blake2B384, () => new Blake2BDigest(384, true) },
                { HashFunction.Blake2B512, () => new Blake2BDigest(512, true) },
                { HashFunction.Keccak224, () => new KeccakDigest(224, true) },
                { HashFunction.Keccak256, () => new KeccakDigest(256, true) },
                { HashFunction.Keccak384, () => new KeccakDigest(384, true) },
                { HashFunction.Keccak512, () => new KeccakDigest(512, true) },
#if INCLUDE_SHA1
                { HashFunction.Sha1, () => new Sha1Digest() },
#endif
                { HashFunction.Sha256, () => new Sha256Digest() },
                { HashFunction.Sha512, () => new Sha512Digest() },
                { HashFunction.Ripemd160, () => new RipeMD160Digest() },
                { HashFunction.Tiger, () => new TigerDigest() }
            };

            // ######################################## MAC FUNCTIONS ########################################
            MacInstantiators = new Dictionary<MacFunction, Func<IMac>> {
                { MacFunction.Blake2B256, () => new Blake2BMac(256, true) },
                { MacFunction.Blake2B384, () => new Blake2BMac(384, true) },
                { MacFunction.Blake2B512, () => new Blake2BMac(512, true) },
                { MacFunction.Keccak224, () => new KeccakMac(224, true) },
                { MacFunction.Keccak256, () => new KeccakMac(256, true) },
                { MacFunction.Keccak384, () => new KeccakMac(384, true) },
                { MacFunction.Keccak512, () => new KeccakMac(512, true) }
            };
        }

        /// <summary>
        ///     Instantiates and returns a hash/digest primitive.
        /// </summary>
        /// <param name="hashEnum">Hash/digest function to instantiate.</param>
        /// <returns>
        ///     An digest object deriving from IDigest.
        /// </returns>
        public static IDigest CreateHashPrimitive(HashFunction hashEnum)
        {
            return DigestInstantiators[hashEnum]();
        }

        public static IDigest CreateHashPrimitive(string hashName)
        {
            return CreateHashPrimitive(hashName.ToEnum<HashFunction>());
        }

        /// <summary>
        ///     Instantiates and initialises a Message Authentication Code (MAC) primitive.
        ///     If salt is used, it is applied as: salt||message, where || is concatenation.
        /// </summary>
        /// <param name="macEnum">MAC function to instantiate.</param>
        /// <param name="key">Cryptographic key to use in the MAC operation.</param>
        /// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
        /// <param name="config">
        ///     Configuration for the function, where applicable. For example,
        ///     CMAC and HMAC use cipher and hash function names, repectively, encoded as UTF-8.
        /// </param>
        /// <param name="nonce">Nonce for the function, where applicable (rare, very specific) - null if N/A.</param>
        /// <returns>
        ///     An MAC object deriving from IMac.
        /// </returns>
        public static IMac CreateMacPrimitive(MacFunction macEnum, byte[] key, byte[] salt = null,
            byte[] config = null, byte[] nonce = null)
        {
            IMac macObj;
            switch (macEnum) {
                case MacFunction.Hmac:
                    if (config == null) {
                        throw new ArgumentException("No hash function specified (encoded as UTF-8 bytes).", "config");
                    }
                    macObj = CreateHmacPrimitive(Encoding.UTF8.GetString(config).ToEnum<HashFunction>(), key, salt);
                    break;
                case MacFunction.Cmac:
                    if (config == null) {
                        throw new ArgumentException("No block cipher specified (encoded as UTF-8 bytes).", "config");
                    }
                    macObj = CreateCmacPrimitive(Encoding.UTF8.GetString(config).ToEnum<BlockCipher>(), key, salt);
                    break;
                case MacFunction.Poly1305:
                    if (config != null && nonce == null) {
                        throw new ArgumentException("No nonce/IV supplied for the block cipher.", "nonce");
                    }
                    macObj = CreatePoly1305Primitive(Encoding.UTF8.GetString(config).ToEnum<BlockCipher>(), key, nonce,
                        salt);
                    break;
                default:
                    macObj = MacInstantiators[macEnum]();
                    macObj.Init(key);
                    if (salt.IsNullOrZeroLength() == false) {
                        macObj.BlockUpdate(salt, 0, salt.Length);
                    }
                    break;
            }

            return macObj;
        }

        public static IMac CreateMacPrimitive(string macName, byte[] key, byte[] salt = null, byte[] config = null,
            byte[] nonce = null)
        {
            return CreateMacPrimitive(macName.ToEnum<MacFunction>(), key, salt, config, nonce);
        }

        /// <summary>
        ///     Creates a CMAC primitive using a symmetric block cipher primitive configured with default block size.
        ///     Default block sizes (and so, output sizes) can be found by querying Athena.
        /// </summary>
        /// <param name="cipherEnum">
        ///     Cipher primitive to use as the basis for the CMAC construction. Block size must be 64 or 128
        ///     bits.
        /// </param>
        /// <param name="key">Cryptographic key to use in the MAC operation.</param>
        /// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
        /// <returns>Pre-initialised CMAC primitive.</returns>
        public static IMac CreateCmacPrimitive(BlockCipher cipherEnum, byte[] key, byte[] salt = null)
        {
            int? defaultBlockSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize;
            if (defaultBlockSize != 64 && defaultBlockSize != 128) {
                throw new NotSupportedException("CMAC/OMAC1 only supports ciphers with 64 / 128 bit block sizes.");
            }
            var macObj = new CMac(CipherFactory.CreateBlockCipher(cipherEnum, null));
            macObj.Init(key);
            if (salt.IsNullOrZeroLength() == false) {
                macObj.BlockUpdate(salt, 0, salt.Length);
            }

            return macObj;
        }

        /// <summary>
        ///     Creates a HMAC primitive using a hash/digest primitive.
        ///     If salt is used, it is applied as: salt||message, where || is concatenation.
        /// </summary>
        /// <param name="hashEnum">Hash/digest primitive to use as the basis for the HMAC construction.</param>
        /// <param name="key">Cryptographic key to use in the MAC operation.</param>
        /// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
        /// <returns>Pre-initialised HMAC primitive.</returns>
        public static IMac CreateHmacPrimitive(HashFunction hashEnum, byte[] key, byte[] salt = null)
        {
            var macObj = new HMac(DigestInstantiators[hashEnum]());
            macObj.Init(key);
            if (salt.IsNullOrZeroLength() == false) {
                macObj.BlockUpdate(salt, 0, salt.Length);
            }

            return macObj;
        }

        /// <summary>
        ///     Creates a Poly1305 primitive using a symmetric block cipher primitive (cipher must have a block size of 128 bits).
        ///     If salt is used, it is applied as: salt||message, where || is concatenation.
        /// </summary>
        /// <param name="cipherEnum">Cipher primitive to use as the basis for the Poly1305 construction.</param>
        /// <param name="key">Cryptographic key to use in the MAC operation.</param>
        /// <param name="nonce">Initialisation vector/nonce. Required.</param>
        /// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
        /// <returns>Pre-initialised Poly1305 MAC primitive.</returns>
        public static IMac CreatePoly1305Primitive(BlockCipher cipherEnum, byte[] key, byte[] nonce, byte[] salt = null)
        {
            if (Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize != 128) {
                throw new NotSupportedException();
            }

            var macObj = new Poly1305Mac(CipherFactory.CreateBlockCipher(cipherEnum));
            macObj.Init(key, nonce);
            if (salt.IsNullOrZeroLength() == false) {
                macObj.BlockUpdate(salt, 0, salt.Length);
            }

            return macObj;
        }
    }
}
