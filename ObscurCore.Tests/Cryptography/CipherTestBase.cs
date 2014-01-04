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
using System.Diagnostics;
using System.IO;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography
{
    public abstract class CipherTestBase : IOTestBase
    {
        protected byte[] Key { get; private set; }

        protected static byte[] CreateRandomKey (int lengthBits) {
            var key = new byte[lengthBits / 8];
            var rng = new Random();
            rng.NextBytes(key);
            return key;
        }

        protected void SetRandomFixtureKey(int lengthBits) { Key = CreateRandomKey(lengthBits); }

        protected void RunEqualityTest (SymmetricCipherConfiguration config, byte[] overrideKey = null) {
            TimeSpan enc, dec;
			MemoryStream fileStream = LargeBinaryFile;

			Assert.IsTrue(OutputNonMalformed(fileStream, config, overrideKey ?? Key, out enc, out dec));

			double encSpeed = ((double) fileStream.Length / 1048576) / enc.TotalSeconds, decSpeed = ((double) fileStream.Length / 1048576) / dec.TotalSeconds;
            Assert.Pass("{0:N0} ms ({1:N2} MB/s) : {2:N0} ms ({3:N2} MB/s)", enc.TotalMilliseconds, encSpeed, dec.TotalMilliseconds, decSpeed);
        }

		protected bool OutputNonMalformed (MemoryStream input, SymmetricCipherConfiguration config, byte[] key, out TimeSpan encryptTime, out TimeSpan decryptTime) {
            var crypted = new MemoryStream();

            var sw = new Stopwatch();
            
			using (var cs = new SymmetricCryptoStream(crypted, true, config, key, false)) {
                sw.Start();
                input.CopyTo(cs, GetBufferSize());
            }
            sw.Stop();
            encryptTime = sw.Elapsed;

            var decrypted = new MemoryStream();
            crypted.Seek(0, SeekOrigin.Begin);

            sw.Reset();
			using (var cs = new SymmetricCryptoStream(crypted, false, config, key, false)) {
                sw.Start();
                cs.CopyTo(decrypted, GetBufferSize());
            }
            sw.Stop();
            decryptTime = sw.Elapsed;

            return decrypted.ToArray().SequenceEqual(input.ToArray());
        }
    }

    public abstract class BlockCipherTestBase : CipherTestBase
    {
        protected SymmetricBlockCipher BlockCipher;
        protected int _defaultBlockSize, _defaultKeySize;

        protected BlockCipherTestBase(SymmetricBlockCipher cipher, int blockSize, int keySize) 
        { 
            BlockCipher = cipher;
            _defaultBlockSize = blockSize;
            _defaultKeySize = keySize;
			SetRandomFixtureKey(_defaultKeySize);
        }

        #region Paddingless modes of operation
        [Test]
        public virtual void CTR () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Ctr,
                                                      BlockCipherPadding.None, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }

        [Test]
        public virtual void CFB () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Cfb,
                                                      BlockCipherPadding.None, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }

        [Test]
        public virtual void OFB () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Ofb,
                                                      BlockCipherPadding.None, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }
        #endregion

        #region CBC with padding modes
        [Test]
        public virtual void CBC_ISO10126D2 () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Cbc,
                                                      BlockCipherPadding.Iso10126D2, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }

        [Test]
        public virtual void CBC_ISO7816D4 () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Cbc,
                                                      BlockCipherPadding.Iso7816D4, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }

        [Test]
        public virtual void CBC_PKCS7 () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Cbc,
                                                      BlockCipherPadding.Pkcs7, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }

        [Test]
        public virtual void CBC_TBC () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Cbc,
                                                      BlockCipherPadding.Tbc, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }

        [Test]
        public virtual void CBC_X923 () {
            // Using default block & key size
            var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher, BlockCipherMode.Cbc,
                                                      BlockCipherPadding.X923, keySize: _defaultKeySize, blockSize: _defaultBlockSize);
            RunEqualityTest(config);
        }
        #endregion
    }
}
