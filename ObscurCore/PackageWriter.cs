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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using LZ4PCL;
using Nessos.LinqOptimizer.CSharp;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyConfirmation;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore
{
    /// <summary>
    ///     Constructs and writes ObscurCore packages.
    /// </summary>
    public sealed class PackageWriter
    {
        private const PayloadLayoutScheme DefaultLayoutScheme = PayloadLayoutScheme.Frameshift;
        private const string MCryptoNotDefined = "Manifest cryptographic scheme not defined.";

        #region Instance variables

        private readonly Dictionary<Guid, byte[]> _itemPreKeys = new Dictionary<Guid, byte[]>();
        private readonly Manifest _manifest;
        private readonly int _formatVersion = Athena.Packaging.PackageFormatVersion;

        /// <summary>
        ///     Configuration of the manifest cipher. Must be serialised into ManifestHeader when writing package.
        /// </summary>
        private IManifestCryptographySchemeConfiguration _manifestHeaderCryptoConfig = null;

        private ManifestCryptographyScheme _manifestHeaderCryptoScheme = ManifestCryptographyScheme.None;

        /// <summary>
        ///     Whether package has had Write() called already in its lifetime.
        ///     Multiple invocations are prohibited in order to preserve security properties.
        /// </summary>
        private bool _writingComplete;

        /// <summary>
        ///     Key for the manifest cipher prior to key derivation.
        /// </summary>
        private byte[] _writingPreManifestKey;

        #endregion

        #region Constructors

        /// <summary>
        ///     Create a new package using default symmetric-only encryption for security.
        /// </summary>
        /// <param name="key">Cryptographic key known to the recipient to use for the manifest.</param>
        /// <param name="lowEntropy">Byte key supplied has low entropy (e.g. from a human password).</param>
        /// <param name="layoutScheme">Scheme to use for the layout of items in the payload.</param>
        public PackageWriter(byte[] key, bool lowEntropy, PayloadLayoutScheme layoutScheme = DefaultLayoutScheme)
        {
            _manifest = new Manifest();
            _manifestHeaderCryptoScheme = ManifestCryptographyScheme.SymmetricOnly;
            SetManifestCryptoSymmetric(key, lowEntropy);
            PayloadLayout = layoutScheme;
            ManifestCompression = true;
        }

        /// <summary>
        ///     Create a new package using default symmetric-only encryption for security.
        ///     Key is used in UTF-8-encoded byte array form.
        /// </summary>
        /// <param name="key">Passphrase known to the recipient to use for the manifest.</param>
        /// <param name="layoutScheme">Scheme to use for the layout of items in the payload.</param>
        public PackageWriter(string key, PayloadLayoutScheme layoutScheme = DefaultLayoutScheme) 
            : this(Encoding.UTF8.GetBytes(key), true, layoutScheme)
        {
        }

        /// <summary>
        ///     Create a new package using UM1-hybrid cryptography for security.
        /// </summary>
        /// <param name="sender">Elliptic curve key of the sender (private key).</param>
        /// <param name="recipient">Elliptic curve key of the recipient (public key).</param>
        /// <param name="layoutScheme">Scheme to use for the layout of items in the payload.</param>
        public PackageWriter(EcKeypair sender, EcKeypair recipient,
            PayloadLayoutScheme layoutScheme = DefaultLayoutScheme)
        {
            _manifest = new Manifest();
            _manifestHeaderCryptoScheme = ManifestCryptographyScheme.Um1Hybrid;
            SetManifestCryptoUm1(sender.GetPrivateKey(), recipient.ExportPublicKey());
            PayloadLayout = layoutScheme;
        }

        /// <summary>
        ///     Initialise a writer without setting any manifest cryptographic scheme. This must be set before writing.
        /// </summary>
        /// <param name="layoutScheme"></param>
        public PackageWriter(PayloadLayoutScheme layoutScheme = DefaultLayoutScheme)
        {
            _manifest = new Manifest();
            _manifestHeaderCryptoScheme = ManifestCryptographyScheme.None;
            _manifestHeaderCryptoConfig = null;
            PayloadLayout = layoutScheme;
        }

        #endregion

        #region  Properties

        /// <summary>
        ///     Format version specification of the data transfer objects and logic used in the package.
        /// </summary>
        public int FormatVersion
        {
            get { return _formatVersion; }
        }

        public bool ManifestCompression { get; set; }

        /// <summary>
        ///     Cryptographic scheme used for the manifest.
        /// </summary>
        public ManifestCryptographyScheme ManifestCryptoScheme
        {
            get { return _manifestHeaderCryptoScheme; }
        }

        /// <summary>
        ///     Configuration of symmetric cipher used for encryption of the manifest.
        /// </summary>
        internal CipherConfiguration ManifestCipher
        {
            get { return _manifestHeaderCryptoConfig == null ? null : _manifestHeaderCryptoConfig.SymmetricCipher; }
            private set
            {
                switch (ManifestCryptoScheme) {
                    case ManifestCryptographyScheme.SymmetricOnly:
                        ((SymmetricManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).SymmetricCipher =
                            value;
                        break;
                    case ManifestCryptographyScheme.Um1Hybrid:
                        ((Um1HybridManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).SymmetricCipher =
                            value;
                        break;
                    default:
                        throw new InvalidOperationException(MCryptoNotDefined);
                }
            }
        }

        /// <summary>
        ///     Configuration of function used in verifying the authenticity and integrity of the manifest.
        /// </summary>
        internal AuthenticationFunctionConfiguration ManifestAuthentication
        {
            get { return _manifestHeaderCryptoConfig == null ? null : _manifestHeaderCryptoConfig.Authentication; }
            private set
            {
                switch (ManifestCryptoScheme) {
                    case ManifestCryptographyScheme.SymmetricOnly:
                        ((SymmetricManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).Authentication =
                            value;
                        break;
                    case ManifestCryptographyScheme.Um1Hybrid:
                        ((Um1HybridManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).Authentication =
                            value;
                        break;
                    default:
                        throw new InvalidOperationException(MCryptoNotDefined);
                }
            }
        }

        /// <summary>
        ///     Configuration of key derivation used to derive encryption and authentication keys from prior key material.
        ///     These keys are used in those functions of manifest encryption/authentication, respectively.
        /// </summary>
        internal KeyDerivationConfiguration ManifestKeyDerivation
        {
            get { return _manifestHeaderCryptoConfig == null ? null : _manifestHeaderCryptoConfig.KeyDerivation; }
            private set
            {
                switch (ManifestCryptoScheme) {
                    case ManifestCryptographyScheme.SymmetricOnly:
                        ((SymmetricManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).KeyDerivation =
                            value;
                        break;
                    case ManifestCryptographyScheme.Um1Hybrid:
                        ((Um1HybridManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).KeyDerivation =
                            value;
                        break;
                    default:
                        throw new InvalidOperationException(MCryptoNotDefined);
                }
            }
        }

        /// <summary>
        ///     Configuration of key confirmation used for confirming the cryptographic key
        ///     to be used as the basis for key derivation.
        /// </summary>
        internal AuthenticationFunctionConfiguration ManifestKeyConfirmation
        {
            get { return _manifestHeaderCryptoConfig == null ? null : _manifestHeaderCryptoConfig.KeyConfirmation; }
            private set
            {
                switch (ManifestCryptoScheme) {
                    case ManifestCryptographyScheme.SymmetricOnly:
                        ((SymmetricManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).KeyConfirmation =
                            value;
                        break;
                    case ManifestCryptographyScheme.Um1Hybrid:
                        ((Um1HybridManifestCryptographyConfiguration) _manifestHeaderCryptoConfig).KeyConfirmation =
                            value;
                        break;
                    default:
                        throw new InvalidOperationException(MCryptoNotDefined);
                }
            }
        }

        /// <summary>
        ///     Layout scheme configuration of the items in the payload.
        /// </summary>
        public PayloadLayoutScheme PayloadLayout
        {
            get { return _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>(); }
            set { _manifest.PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(value); }
        }

        #endregion

        #region Methods for manifest cryptography

        /// <summary>
        ///     Set the manifest to use symmetric-only security.
        ///     Key is used in UTF-8 encoded byte array form.
        /// </summary>
        /// <param name="key">Passphrase known to the recipient of the package.</param>
        /// <exception cref="ArgumentException">Key is null or zero-length.</exception>
        public void SetManifestCryptoSymmetric(string key)
        {
            if (String.IsNullOrEmpty(key)) {
                throw new ArgumentException("Key is null or zero-length (empty).", "key");
            }

            SetManifestCryptoSymmetric(Encoding.UTF8.GetBytes(key), true);
        }

        /// <summary>
        ///     Set the manifest to use symmetric-only security.
        /// </summary>
        /// <param name="key">Key known to the recipient of the package.</param>
        /// <param name="lowEntropy">Pre-key has low entropy, e.g. a human-memorisable passphrase.</param>
        /// <exception cref="ArgumentException">Key is null or zero-length.</exception>
        public void SetManifestCryptoSymmetric(byte[] key, bool lowEntropy)
        {
            if (key.IsNullOrZeroLength()) {
                throw new ArgumentException("Key is null or zero-length.", "key");
            }

            if (_writingPreManifestKey != null) {
                _writingPreManifestKey.SecureWipe();
            }

            _writingPreManifestKey = new byte[key.Length];
            Array.Copy(key, _writingPreManifestKey, key.Length);
            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "SetManifestCryptoSymmetric",
                "Manifest pre-key",
                _writingPreManifestKey.ToHexString()));

            CipherConfiguration cipherConfig = _manifestHeaderCryptoConfig == null
                ? CreateDefaultManifestCipherConfiguration()
                : _manifestHeaderCryptoConfig.SymmetricCipher ?? CreateDefaultManifestCipherConfiguration();

            AuthenticationFunctionConfiguration authenticationConfig = _manifestHeaderCryptoConfig == null
                ? CreateDefaultManifestAuthenticationConfiguration()
                : _manifestHeaderCryptoConfig.Authentication ?? CreateDefaultManifestAuthenticationConfiguration();

            KeyDerivationConfiguration derivationConfig = _manifestHeaderCryptoConfig == null
                ? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8, lowEntropy)
                : _manifestHeaderCryptoConfig.KeyDerivation ??
                  CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8);

            byte[] keyConfirmationOutput;
            AuthenticationFunctionConfiguration keyConfirmationConfig = CreateDefaultManifestKeyConfirmationConfiguration(
                _writingPreManifestKey, out keyConfirmationOutput);

            _manifestHeaderCryptoConfig = new SymmetricManifestCryptographyConfiguration {
                SymmetricCipher = cipherConfig,
                Authentication = authenticationConfig,
                KeyConfirmation = keyConfirmationConfig,
                KeyConfirmationVerifiedOutput = keyConfirmationOutput,
                KeyDerivation = derivationConfig
            };
            _manifestHeaderCryptoScheme = ManifestCryptographyScheme.SymmetricOnly;
        }

        /// <summary>
        ///     Set manifest to use UM1-Hybrid cryptography.
        /// </summary>
        /// <param name="senderKey">Key of the sender (private key).</param>
        /// <param name="receiverKey">Key of the recipient (public key).</param>
        public void SetManifestCryptoUm1(EcKeyConfiguration senderKey, EcKeyConfiguration receiverKey)
        {
            if (senderKey == null) {
                throw new ArgumentNullException("senderKey");
            }
            if (receiverKey == null) {
                throw new ArgumentNullException("receiverKey");
            }

            if (senderKey.CurveName.Equals(receiverKey.CurveName) == false) {
                throw new InvalidOperationException(
                    "Elliptic curve cryptographic mathematics requires public and private keys be in the same curve domain.");
            }

            EcKeyConfiguration ephemeral;
            _writingPreManifestKey = Um1Exchange.Initiate(receiverKey, senderKey, out ephemeral);
            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "SetManifestCryptoUM1", "Manifest pre-key",
                _writingPreManifestKey.ToHexString()));

            CipherConfiguration cipherConfig = _manifestHeaderCryptoConfig == null
                ? CreateDefaultManifestCipherConfiguration()
                : _manifestHeaderCryptoConfig.SymmetricCipher ?? CreateDefaultManifestCipherConfiguration();

            AuthenticationFunctionConfiguration authenticationConfig = _manifestHeaderCryptoConfig == null
                ? CreateDefaultManifestAuthenticationConfiguration()
                : _manifestHeaderCryptoConfig.Authentication ?? CreateDefaultManifestAuthenticationConfiguration();

            KeyDerivationConfiguration derivationConfig = _manifestHeaderCryptoConfig == null
                ? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8, false)
                : _manifestHeaderCryptoConfig.KeyDerivation ??
                  CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8);

            byte[] keyConfirmationOutput;
            AuthenticationFunctionConfiguration keyConfirmationConfig = CreateDefaultManifestKeyConfirmationConfiguration(
                _writingPreManifestKey, out keyConfirmationOutput);

            _manifestHeaderCryptoConfig = new Um1HybridManifestCryptographyConfiguration {
                SymmetricCipher = cipherConfig,
                Authentication = authenticationConfig,
                KeyConfirmation = keyConfirmationConfig,
                KeyConfirmationVerifiedOutput = keyConfirmationOutput,
                KeyDerivation = derivationConfig,
                EphemeralKey = ephemeral
            };
            _manifestHeaderCryptoScheme = ManifestCryptographyScheme.Um1Hybrid;
        }

        /// <summary>
        ///     Advanced method. Manually set a manifest cryptography configuration.
        ///     Misuse will likely result in unreadable package, and/or security risks.
        /// </summary>
        /// <param name="configuration">Configuration to apply.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="ArgumentException">Object not a recognised type.</exception>
        /// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
        public void SetManifestCryptography(IManifestCryptographySchemeConfiguration configuration)
        {
            if (configuration is IDataTransferObject) {
                if (configuration is SymmetricManifestCryptographyConfiguration) {
                    _manifestHeaderCryptoScheme = ManifestCryptographyScheme.SymmetricOnly;
                    _manifestHeaderCryptoConfig = configuration;
                } else if (configuration is Um1HybridManifestCryptographyConfiguration) {
                    _manifestHeaderCryptoScheme = ManifestCryptographyScheme.Um1Hybrid;
                    _manifestHeaderCryptoConfig = configuration;
                } else {
                    throw new ArgumentException("Configuration provided is of an unsupported type.",
                        new NotSupportedException(""));
                }
            } else {
                throw new ArgumentException(
                    "Object is not a valid data transfer object type in the ObscurCore package format specification.",
                    "configuration");
            }
        }

        /// <summary>
        ///     Set a specific block cipher configuration to be used for the cipher used for manifest encryption.
        /// </summary>
        /// <exception cref="InvalidOperationException">Package is being written, not read.</exception>
        /// <exception cref="ArgumentException">Enum was set to None.</exception>
        public void ConfigureManifestCryptoSymmetric(BlockCipher cipher, BlockCipherMode mode,
            BlockCipherPadding padding)
        {
            if (cipher == BlockCipher.None) {
                throw new ArgumentException("Cipher cannot be set to none.", "cipher");
            }
            if (mode == BlockCipherMode.None) {
                throw new ArgumentException("Mode cannot be set to none.", "mode");
            }
            if (cipher == BlockCipher.None) {
                throw new ArgumentException();
            }

            ManifestCipher = CipherConfigurationFactory.CreateBlockCipherConfiguration(cipher, mode, padding);
        }

        /// <summary>
        ///     Set a specific stream cipher to be used for the cipher used for manifest encryption.
        /// </summary>
        /// <exception cref="InvalidOperationException">Package is being written, not read.</exception>
        /// <exception cref="ArgumentException">Cipher was set to None.</exception>
        public void ConfigureManifestCryptoSymmetric(StreamCipher cipher)
        {
            if (cipher == StreamCipher.None) {
                throw new ArgumentException();
            }

            ManifestCipher = CipherConfigurationFactory.CreateStreamCipherConfiguration(cipher);
        }

        /// <summary>
        ///     Advanced method. Manually set a payload configuration for the package.
        /// </summary>
        /// <param name="payloadConfiguration">Payload configuration to set.</param>
        /// <exception cref="ArgumentNullException">Payload configuration is null.</exception>
        public void SetPayloadConfiguration(PayloadConfiguration payloadConfiguration)
        {
            if (payloadConfiguration == null) {
                throw new ArgumentNullException("payloadConfiguration");
            }
            _manifest.PayloadConfiguration = payloadConfiguration;
        }

        // Manifest default configuration creation methods

        /// <summary>
        ///     Creates a default manifest cipher configuration.
        /// </summary>
        /// <remarks>Default configuration uses the stream cipher XSalsa20.</remarks>
        private static CipherConfiguration CreateDefaultManifestCipherConfiguration()
        {
            return CipherConfigurationFactory.CreateStreamCipherConfiguration(StreamCipher.XSalsa20);
        }

        /// <summary>
        ///     Creates a default manifest authentication configuration.
        /// </summary>
        /// <remarks>Default configuration uses the MAC primitive SHA-3-512 (Keccak-512).</remarks>
        /// <returns></returns>
        private static AuthenticationFunctionConfiguration CreateDefaultManifestAuthenticationConfiguration()
        {
            int outputSize;
            return AuthenticationConfigurationFactory.CreateAuthenticationConfiguration(MacFunction.Keccak512,
                out outputSize);
        }

        /// <summary>
        ///     Creates a default manifest key confirmation configuration.
        /// </summary>
        /// <remarks>Default configuration uses HMAC-SHA3-256 (HMAC-Keccak-256).</remarks>
        /// <param name="key">Key to generate confirmation configuration for.</param>
        /// <param name="verifiedOutput">Output of verification function.</param>
        private static AuthenticationFunctionConfiguration CreateDefaultManifestKeyConfirmationConfiguration(byte[] key,
            out byte[] verifiedOutput)
        {
            AuthenticationFunctionConfiguration config =
                ConfirmationConfigurationFactory.GenerateConfiguration(HashFunction.Keccak256);
            // Using HMAC (key can be any length)
            verifiedOutput = ConfirmationUtility.GenerateVerifiedOutput(config, key);

            return config;
        }

        /// <summary>
        ///     Creates a default manifest key derivation configuration.
        /// </summary>
        /// <remarks>Default configuration uses the KDF function 'scrypt'.</remarks>
        /// <param name="keyLengthBytes">Length of key to produce.</param>
        /// <param name="lowEntropyPreKey">Pre-key has low entropy, e.g. a human-memorisable passphrase.</param>
        private static KeyDerivationConfiguration CreateDefaultManifestKeyDerivation(int keyLengthBytes,
            bool lowEntropyPreKey = true)
        {
            var schemeConfig = new ScryptConfiguration {
                Iterations = lowEntropyPreKey ? 65536 : 1024, // 2^16 : 2^10
                Blocks = lowEntropyPreKey ? 16 : 8,
                Parallelism = 2
            };
            var config = new KeyDerivationConfiguration {
                FunctionName = KeyDerivationFunction.Scrypt.ToString(),
                FunctionConfiguration = schemeConfig.SerialiseDto(),
                Salt = new byte[keyLengthBytes]
            };
            StratCom.EntropySupplier.NextBytes(config.Salt);
            return config;
        }

        #endregion

        #region Methods for payload items

        /// <summary>
        ///     Add a text payload item (encoded in UTF-8) to the package with a relative path
        ///     of root (/) in the manifest. Default encryption is used.
        /// </summary>
        /// <param name="name">Name of the item. Subject of the text is suggested.</param>
        /// <param name="text">Content of the item.</param>
        /// <exception cref="ArgumentException">Supplied null or empty string.</exception>
        public void AddText(string name, string text)
        {
            if (String.IsNullOrEmpty(name) || String.IsNullOrWhiteSpace(name)) {
                throw new ArgumentException("Item name is null or empty string.");
            }
            var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));
            PayloadItem newItem = CreateItem(() => stream, PayloadItemType.Message, stream.Length, name);

            _manifest.PayloadItems.Add(newItem);
        }

        /// <summary>
        ///     Add a file-type payload item to the package with a relative path of root (/) in the manifest.
        ///     Default encryption is used.
        /// </summary>
        /// <param name="filePath">Path of the file to add.</param>
        /// <exception cref="FileNotFoundException">File does not exist.</exception>
        public void AddFile(string filePath)
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Exists == false) {
                throw new FileNotFoundException();
            }

            PayloadItem newItem = CreateItem(fileInfo.OpenRead, PayloadItemType.File, fileInfo.Length, fileInfo.Name);
            _manifest.PayloadItems.Add(newItem);
        }

        /// <summary>
        ///     Add a directory of files as payload items to the package with a relative path
        ///     of root (/) in the manifest. Default encryption is used.
        /// </summary>
        /// <param name="path">Path of the directory to search for and add files from.</param>
        /// <param name="search">Search for files in subdirectories (default) or not.</param>
        /// <exception cref="ArgumentException">Path supplied is not a directory.</exception>
        public void AddDirectory(string path, SearchOption search = SearchOption.TopDirectoryOnly)
        {
            var dir = new DirectoryInfo(path);

            if (Path.HasExtension(path)) {
                throw new ArgumentException("Path is not a directory.");
            }
            if (!dir.Exists) {
                throw new DirectoryNotFoundException();
            }

            int rootPathLength = dir.FullName.Length;
            IEnumerable<FileInfo> files = dir.EnumerateFiles("*", search);
            foreach (FileInfo file in files) {
                string itemRelPath = search == SearchOption.TopDirectoryOnly
                    ? file.Name
                    : file.FullName.Remove(0, rootPathLength + 1);
                if (Path.DirectorySeparatorChar != Athena.Packaging.PathDirectorySeperator) {
                    itemRelPath = itemRelPath.Replace(Path.DirectorySeparatorChar,
                        Athena.Packaging.PathDirectorySeperator);
                }
                PayloadItem newItem = CreateItem(file.OpenRead, PayloadItemType.File, file.Length, itemRelPath);

                _manifest.PayloadItems.Add(newItem);
            }
        }

        /// <summary>
        ///     Add a payload item to the package.
        /// </summary>
        /// <exception cref="ArgumentNullException">Payload item argument is null.</exception>
        public void AddFile(PayloadItem item)
        {
            if (item == null) {
                throw new ArgumentNullException("item");
            }

            _manifest.PayloadItems.Add(item);
        }

        public IEnumerable<IPayloadItem> GetPayloadItems()
        {
            return _manifest.PayloadItems.AsQueryExpr().Select(item => item as IPayloadItem).Run();
        }

        /// <summary>
        ///     Creates a new PayloadItem DTO object.
        /// </summary>
        /// <returns>A payload item as a <see cref="PayloadItem" /> 'data transfer object'.</returns>
        /// <param name="itemData">Function supplying a stream of the item data.</param>
        /// <param name="itemType">Type of the item (as <see cref="PayloadItemType"/>).</param>
        /// <param name="externalLength">External length (outside the payload) of the item.</param>
        /// <param name="relativePath">Relative path of the item.</param>
        /// <param name="skipCrypto">
        ///     If set to <c>true</c>, leaves SymmetricCipher property set to null -
        ///     for post-method-modification.
        /// </param>
        private static PayloadItem CreateItem(Func<Stream> itemData, PayloadItemType itemType, long externalLength,
            string relativePath, bool skipCrypto = false)
        {
            var newItem = new PayloadItem {
                ExternalLength = externalLength,
                Type = itemType,
                Path = relativePath,
                SymmetricCipher = skipCrypto ? null : CreateDefaultPayloadItemCipherConfiguration(),
                Authentication = skipCrypto ? null : CreateDefaultPayloadItemAuthenticationConfiguration()
            };

            if (skipCrypto == false) {
                newItem.SymmetricCipherKey = new byte[newItem.SymmetricCipher.KeySizeBits / 8];
                StratCom.EntropySupplier.NextBytes(newItem.SymmetricCipherKey);
                newItem.AuthenticationKey = new byte[newItem.Authentication.KeySizeBits.Value / 8];
                StratCom.EntropySupplier.NextBytes(newItem.AuthenticationKey);
            }

            newItem.SetStreamBinding(itemData);
            return newItem;
        }

        /// <summary>
        ///     Creates a new PayloadItem DTO object with a specific cryptographic key.
        /// </summary>
        /// <returns>A payload item as a <see cref="ObscurCore.DTO.PayloadItem" /> 'data transfer object'.</returns>
        /// <param name="itemData">Function supplying a stream of the item data.</param>
        /// <param name="itemType">Type of the item (as <see cref="PayloadItemType"/>).</param>
        /// <param name="externalLength">External length (outside the payload) of the item.</param>
        /// <param name="relativePath">Relative path of the item.</param>
        /// <param name="preKey">Key to be found on recipient's system and used as a basis for derivation.</param>
        /// <param name="lowEntropyKey">
        ///     If set to <c>true</c> pre-key has low entropy (e.g. a human-memorisable passphrase), and higher KDF difficulty will
        ///     be used.
        /// </param>
        private static PayloadItem CreateItem(Func<Stream> itemData, PayloadItemType itemType, long externalLength,
            string relativePath, byte[] preKey, bool lowEntropyKey = true)
        {
            byte[] keyConfirmationVerifiedOutput;
            AuthenticationFunctionConfiguration keyConfirmatConf =
                CreateDefaultPayloadItemKeyConfirmationConfiguration(preKey,
                    out keyConfirmationVerifiedOutput);
            KeyDerivationConfiguration kdfConf = CreateDefaultPayloadItemKeyDerivation(preKey.Length, lowEntropyKey);

            var newItem = new PayloadItem {
                ExternalLength = externalLength,
                Type = itemType,
                Path = relativePath,
                SymmetricCipher = CreateDefaultPayloadItemCipherConfiguration(),
                Authentication = CreateDefaultPayloadItemAuthenticationConfiguration(),
                KeyConfirmation = keyConfirmatConf,
                KeyConfirmationVerifiedOutput = keyConfirmationVerifiedOutput,
                KeyDerivation = kdfConf
            };

            newItem.SetStreamBinding(itemData);
            return newItem;
        }

        // Payload item default configuration creation methods

        /// <summary>
        ///     Creates a default payload item cipher configuration.
        /// </summary>
        /// <remarks>Default configuration uses the stream cipher HC-128.</remarks>
        private static CipherConfiguration CreateDefaultPayloadItemCipherConfiguration()
        {
            return CipherConfigurationFactory.CreateStreamCipherConfiguration(StreamCipher.Hc128);
        }

        /// <summary>
        ///     Creates a default payload item authentication configuration.
        /// </summary>
        /// <remarks>Default configuration uses the hybrid MAC-cipher construction Poly1305-AES.</remarks>
        private static AuthenticationFunctionConfiguration CreateDefaultPayloadItemAuthenticationConfiguration()
        {
            return AuthenticationConfigurationFactory.CreateAuthenticationConfigurationPoly1305(BlockCipher.Aes);
        }

        /// <summary>
        ///     Creates a default payload item key confirmation configuration.
        /// </summary>
        /// <remarks>Default configuration uses HMAC-SHA3-256 (HMAC-Keccak-256).</remarks>
        /// <param name="key">Key to generate confirmation configuration for.</param>
        /// <param name="verifiedOutput">Output of verification function.</param>
        private static AuthenticationFunctionConfiguration CreateDefaultPayloadItemKeyConfirmationConfiguration(
            byte[] key, out byte[] verifiedOutput)
        {
            AuthenticationFunctionConfiguration config =
                ConfirmationConfigurationFactory.GenerateConfiguration(HashFunction.Keccak256);
            verifiedOutput = ConfirmationUtility.GenerateVerifiedOutput(config, key);

            return config;
        }

        /// <summary>
        ///     Creates a default payload item key derivation configuration.
        /// </summary>
        /// <remarks>Default configuration uses the KDF function 'scrypt'.</remarks>
        /// <param name="keyLengthBytes">Length of key to produce.</param>
        /// <param name="lowEntropyPreKey">Pre-key has low entropy, e.g. a human-memorisable passphrase.</param>
        private static KeyDerivationConfiguration CreateDefaultPayloadItemKeyDerivation(int keyLengthBytes,
            bool lowEntropyPreKey = true)
        {
            var schemeConfig = new ScryptConfiguration {
                Iterations = lowEntropyPreKey ? 16384 : 1024, // 2^14 : 2^10
                Blocks = 8,
                Parallelism = 1
            };
            var config = new KeyDerivationConfiguration {
                FunctionName = KeyDerivationFunction.Scrypt.ToString(),
                FunctionConfiguration = schemeConfig.SerialiseDto(),
                Salt = new byte[keyLengthBytes]
            };
            StratCom.EntropySupplier.NextBytes(config.Salt);
            return config;
        }

        #endregion

        /// <summary>
        ///     Write package out to bound stream.
        /// </summary>
        /// <param name="outputStream">Stream which the package is to be written to.</param>
        /// <param name="closeOnComplete">Whether to close the destination stream upon completion of writing.</param>
        /// <param name="tempOutputStream">Storage for temporary data written during the writing process. If null, to memory.</param>
        /// <exception cref="NotSupportedException">Unsupported manifest cryptographic scheme attempted to be used.</exception>
        /// <exception cref="InvalidOperationException">Package state incomplete, or attempted to write package twice.</exception>
        /// <exception cref="AggregateException">
        ///     Collection of however many items have no stream bindings (as <see cref="ItemStreamBindingAbsentException" />)
        ///     or keys (as <see cref="ItemStreamBindingAbsentException" />).
        /// </exception>
        public void Write(Stream outputStream, bool closeOnComplete = true, Stream tempOutputStream = null)
        {
            // Sanity checks
            if (_writingComplete) {
                throw new InvalidOperationException(
                    "Multiple writes from one package are not supported; it may compromise security properties.");
            }
            if (_manifestHeaderCryptoConfig == null) {
                throw new ConfigurationInvalidException(
                    "Manifest cryptography scheme and its configuration is not set up.");
            }
            if (_manifest.PayloadItems.Count == 0) {
                throw new InvalidOperationException("No payload items have been added.");
            }
            if (outputStream == null) {
                throw new ArgumentNullException("outputStream");
            }
            if (outputStream == Stream.Null) {
                throw new ArgumentException("Stream is set to where bits go to die.", "outputStream");
            }
            if (outputStream.CanWrite == false) {
                throw new IOException("Cannot write to output stream.");
            }
            if (tempOutputStream != null && tempOutputStream.CanWrite == false) {
                throw new ArgumentException("Cannot write to temporary output stream.", "tempOutputStream");
            }
            if (tempOutputStream == Stream.Null) {
                throw new ArgumentException("Stream is set to where bits go to die.", "tempOutputStream");
            }

            // Check if any payload items are missing stream bindings or keys before proceeding
            IEnumerable<ItemStreamBindingAbsentException> streamBindingAbsentExceptions =
                (from item in _manifest.PayloadItems.AsQueryExpr()
                 where item.StreamHasBinding == false
                 select new ItemStreamBindingAbsentException(item)).Run();

            IEnumerable<ItemKeyMissingException> keyMissingExceptions =
                (from payloadItem in _manifest.PayloadItems.AsQueryExpr()
                 where _itemPreKeys.ContainsKey(payloadItem.Identifier) == false
                       && (payloadItem.SymmetricCipherKey.IsNullOrZeroLength()
                           || payloadItem.AuthenticationKey.IsNullOrZeroLength())
                 select new ItemKeyMissingException(payloadItem)).Run();

            IEnumerable<Exception> streamOrKeyExceptions =
                streamBindingAbsentExceptions.Concat<Exception>(keyMissingExceptions);
            if (streamOrKeyExceptions.Any()) {
                throw new AggregateException(streamOrKeyExceptions);
            }

            if (tempOutputStream == null) {
                // Default to writing to memory
                int totalLen =
                    _manifest.PayloadItems.AsQueryExpr().Aggregate(0, (i, item) => (int) item.ExternalLength).Run();
                var expLen = (int) (totalLen * 1.1);
                Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write",
                    "Preallocated memory for payload (total -> allocated)", totalLen + " -> " + expLen));
                tempOutputStream = new MemoryStream(expLen);
            }

            // Write the header tag
            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write", "[*PACKAGE START*] Offset",
                outputStream.Position));
            byte[] headerTag = Athena.Packaging.GetPackageHeaderTag();
            outputStream.Write(headerTag, 0, headerTag.Length);

            /* Derive working manifest encryption & authentication keys from the manifest pre-key */
            byte[] workingManifestCipherKey, workingManifestMacKey;
            Debug.Assert(_manifestHeaderCryptoConfig.Authentication.KeySizeBits != null,
                "Manifest authentication key size should not be null");
            KeyStretchingUtility.DeriveWorkingKeys(_writingPreManifestKey,
                _manifestHeaderCryptoConfig.SymmetricCipher.KeySizeBits / 8,
                _manifestHeaderCryptoConfig.Authentication.KeySizeBits.Value / 8,
                _manifestHeaderCryptoConfig.KeyDerivation,
                out workingManifestCipherKey, out workingManifestMacKey);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write", "Manifest working key",
                workingManifestCipherKey.ToHexString()));

            // Write the payload to temporary storage (tempOutputStream)
            PayloadLayoutScheme payloadScheme;
            try {
                payloadScheme = _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>();
            } catch (Exception) {
                throw new ConfigurationInvalidException(
                    "Package payload schema specified is unsupported/unknown or missing.");
            }
            // Bind the multiplexer to the temp stream
            PayloadMux mux = PayloadMultiplexerFactory.CreatePayloadMultiplexer(payloadScheme, true, tempOutputStream,
                _manifest.PayloadItems, _itemPreKeys, _manifest.PayloadConfiguration);

            try {
                mux.Execute();
            } catch (Exception) {
                throw;
            }

            // Write the manifest in encrypted + authenticated form to memory at first, then to actual output
            using (var manifestTemp = new MemoryStream()) {
                byte[] manifestMac = null;
                using (
                var authenticator = new MacStream(manifestTemp, true, _manifestHeaderCryptoConfig.Authentication,
                    out manifestMac, workingManifestMacKey, false)) 
                {
                    using (var encryptor = new CipherStream(authenticator, true, _manifestHeaderCryptoConfig.SymmetricCipher,
                        workingManifestCipherKey, false)) 
                    {
                        if (ManifestCompression) {
                            using (var compressor = new LZ4Stream(encryptor, CompressionMode.Compress)) {
                                _manifest.SerialiseDto(compressor, prefixLength:false);
                            }
                        } else {
                            _manifest.SerialiseDto(encryptor, prefixLength: false);
                        }
                    }
                    authenticator.Update(((UInt32)authenticator.BytesOut).ToLittleEndian(), 0, sizeof(UInt32));

                    byte[] manifestCryptoDtoForAuth;
                    switch (ManifestCryptoScheme) {
                        case ManifestCryptographyScheme.SymmetricOnly:
                            var symConfig = _manifestHeaderCryptoConfig as SymmetricManifestCryptographyConfiguration;
                            Debug.Assert(symConfig != null, "'symConfig' is null - casting of '_manifestHeaderCryptoConfig' must have failed.");
                            manifestCryptoDtoForAuth = symConfig.CreateAuthenticatibleClone().SerialiseDto();
                            break;
                        case ManifestCryptographyScheme.Um1Hybrid:
                            var um1Config = _manifestHeaderCryptoConfig as Um1HybridManifestCryptographyConfiguration;
                            Debug.Assert(um1Config != null, "um1Config is null - casting of '_manifestHeaderCryptoConfig' must have failed.");
                            manifestCryptoDtoForAuth = um1Config.CreateAuthenticatibleClone().SerialiseDto();
                            break;
                        default:
                            throw new NotSupportedException();
                    }
                    authenticator.Update(manifestCryptoDtoForAuth, 0, manifestCryptoDtoForAuth.Length);
                }

                // Combine manifest header information (in seperate pieces until now) into a completed DTO
                var mh = new ManifestHeader {
                    FormatVersion = _formatVersion,
                    CryptographySchemeName = _manifestHeaderCryptoScheme.ToString(),
                    UseCompression = this.ManifestCompression
                };
                Debug.Assert(manifestMac != null, "'manifestMac' is null. It should have been set when 'authenticator' was closed.");
                switch (ManifestCryptoScheme) {
                    case ManifestCryptographyScheme.SymmetricOnly:
                        var symConfig = (SymmetricManifestCryptographyConfiguration)_manifestHeaderCryptoConfig;
                        symConfig.AuthenticationVerifiedOutput = manifestMac;
                        mh.CryptographySchemeConfiguration = symConfig.SerialiseDto();
                        break;
                    case ManifestCryptographyScheme.Um1Hybrid:
                        var um1Config = (Um1HybridManifestCryptographyConfiguration)_manifestHeaderCryptoConfig;
                        um1Config.AuthenticationVerifiedOutput = manifestMac;
                        mh.CryptographySchemeConfiguration = um1Config.SerialiseDto();
                        break;
                }

                // Serialise and write ManifestHeader
                Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write", "Manifest header offset",
                    outputStream.Position));
                mh.SerialiseDto(outputStream, prefixLength:true);

                Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write",
                    "Manifest length prefix offset (absolute)",
                    outputStream.Position));
                // Generate length prefix as 32b little-endian unsigned integer
                byte[] manifestLengthHeaderLe = ((UInt32) manifestTemp.Length).ToLittleEndian();
                Debug.Assert(manifestLengthHeaderLe.Length == sizeof (UInt32));
                // Obfuscate the manifest length header by XORing it with the derived manifest MAC (authentication) key
                manifestLengthHeaderLe.XorInPlaceInternal(0, workingManifestMacKey, 0, sizeof (UInt32));
                // Write the now-obfuscated manifest length header
                outputStream.Write(manifestLengthHeaderLe, 0, sizeof (UInt32));
                Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write", "Manifest offset (absolute)",
                    outputStream.Position));

                // Write manifest!
                manifestTemp.WriteTo(outputStream);
            }

            // Clear manifest keys from memory
            Array.Clear(workingManifestCipherKey, 0, workingManifestCipherKey.Length);
            Array.Clear(workingManifestMacKey, 0, workingManifestMacKey.Length);

            // Write out payload currently in temporary storage to real output stream
            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write", "Payload offset (absolute)",
                outputStream.Position));
            tempOutputStream.Seek(0, SeekOrigin.Begin);
            tempOutputStream.CopyTo(outputStream);
            tempOutputStream.Close();

            // Write the trailer tag
            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write", "Trailer offset (absolute)",
                outputStream.Position));
            byte[] trailerTag = Athena.Packaging.GetPackageTrailerTag();
            outputStream.Write(trailerTag, 0, trailerTag.Length);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "Write", "[* PACKAGE END *] Offset (absolute)",
                outputStream.Position));

            // All done!
            if (closeOnComplete) {
                outputStream.Close();
            }
            _writingComplete = true;
        }
    }
}
