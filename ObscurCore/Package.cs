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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyConfirmation;
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.EllipticCurve;
using ObscurCore.Extensions.Streams;
using ObscurCore.Packaging;

namespace ObscurCore
{
    /// <summary>
    /// Virtual object that provides read/write capabilities for packages.
    /// </summary>
    public sealed class Package
    {
        private const int MaximumPayloadOffset = 64;

        // General fields

        /// <summary>
        /// Whether package is being read. Referenced by both modes.
        /// </summary>
        private readonly bool _reading;

        private readonly Manifest _manifest;
        private readonly ManifestHeader _manifestHeader;

        // Writing fields

        /// <summary>
        /// Stream that package is being read from. Only used in reading mode.
        /// </summary>
        private readonly Stream _readingStream;

        /// <summary>
        /// Offset at which the payload starts. Used in reading only.
        /// </summary>
        private long _readingPayloadStreamOffset;

        /// <summary>
        /// Stream bound to memory or disk serving as storage for the payload during a write. 
        /// Uses memory by default. Larger writes should use disk-backed streams.
        /// </summary>
        private Stream _writingTempStream;

        /// <summary>
        /// Whether package has had Write() called already in its lifetime. 
        /// Multiple invocations are prohibited in order to preserve security properties.
        /// </summary>
        private bool _writingComplete;

        /// <summary>
        /// Configuration of the manifest cipher. Must be serialised into ManifestHeader when writing package.
        /// </summary>
        private IManifestCryptographySchemeConfiguration _manifestCryptoConfig;

        /// <summary>
        /// Key for the manifest cipher prior to key derivation. Only used in writing.
        /// </summary>
        private byte[] _writingPreManifestKey;

        // Properties

        /// <summary>
        /// Format version specification of the data transfer objects and logic used in the package.
        /// </summary>
        public int FormatVersion
		{
			get { return _manifestHeader.FormatVersion; }
		}

        /// <summary>
        /// Cryptographic scheme used for the manifest.
        /// </summary>
        public ManifestCryptographyScheme ManifestCryptoScheme 
        {
            get { return _manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>(); }
        }

        /// <summary>
        /// Configuration of cryptography used for the manifest.
        /// </summary>
        /// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
        internal SymmetricCipherConfiguration ManifestCipher {
            get { return _manifestCryptoConfig.SymmetricCipher; }
            set {
                if (_reading) {
                    throw new InvalidOperationException("Cannot change manifest cryptography of existing package.");
                }
                switch (ManifestCryptoScheme) {
                    case ManifestCryptographyScheme.SymmetricOnly:
                        ((SymmetricManifestCryptographyConfiguration)_manifestCryptoConfig).SymmetricCipher = value;
                        break;
                    case ManifestCryptographyScheme.UM1Hybrid:
                        ((UM1ManifestCryptographyConfiguration)_manifestCryptoConfig).SymmetricCipher = value;
                        break;
                    case ManifestCryptographyScheme.Curve25519UM1Hybrid:
                        ((Curve25519UM1ManifestCryptographyConfiguration)_manifestCryptoConfig).SymmetricCipher = value;
                        break;
                }
            }
        }

        /// <summary>
        /// Offset of payload from the manifest.
        /// </summary>
        /// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Offset is outside allowed range.</exception>
        public int PayloadOffset {
            get { return _manifest.PayloadConfiguration.Offset; }
            set {
                if (_reading) {
                    throw new InvalidOperationException("Cannot change payload offset of existing package.");
                }
                if (!value.IsBetween(0, MaximumPayloadOffset)) {
                    throw new ArgumentOutOfRangeException();
                }
                _manifest.PayloadConfiguration.Offset = value;
            }
        }

        /// <summary>
        /// Layout scheme configuration of the items in the payload.
        /// </summary>
        /// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
        public PayloadLayoutScheme LayoutScheme
        {
            get {
                return _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>();
            }
            set {
                if (_reading) {
                    throw new InvalidOperationException("Cannot change layout scheme of existing package.");
                }
                _manifest.PayloadConfiguration = PayloadLayoutConfigurationFactory.CreateDefault(value);
            }
        }

        /// <summary>
        /// Advanced method. Manually set a payload configuration for the package.
        /// </summary>
        /// <param name="payloadConfiguration">Payload configuration to set.</param>
        /// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
        public void SetPayloadConfiguration(PayloadConfiguration payloadConfiguration) {
            if (_reading) {
                throw new InvalidOperationException("Cannot change payload configuration of existing package.");
            }
            if (payloadConfiguration == null) {
                throw new ArgumentNullException("payloadConfiguration");
            }
            _manifest.PayloadConfiguration = payloadConfiguration;
        }

        // Constructors

        /// <summary>
        /// Create a new package using default symmetric-only encryption for security.
        /// </summary>
        /// <param name="key">Cryptographic key known to the receiver to use for the manifest.</param>
        /// <param name="layoutScheme">Scheme to use for the layout of items in the payload.</param>
        public Package(byte[] key, PayloadLayoutScheme layoutScheme = PayloadLayoutScheme.Frameshift) {
            _reading = false;
            _manifest = new Manifest();
            _manifestHeader = new ManifestHeader
                {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographyScheme.SymmetricOnly.ToString()
                };
            SetManifestCryptoSymmetric(key);
            LayoutScheme = layoutScheme;
        }

        /// <summary>
        /// Create a new package for writing using Curve25519-UM1 encryption for security.
        /// A default configuration for the internal cipher will be used.
        /// </summary>
        /// <param name="senderKey">Key of the sender (private key).</param>
        /// <param name="receiverKey">Key of the receiver (public key).</param>
        /// <param name="layoutScheme">Scheme to use for the layout of items in the payload.</param>
        public Package(byte[] senderKey, byte[] receiverKey, PayloadLayoutScheme layoutScheme = PayloadLayoutScheme.Frameshift) {
            _reading = false;
            _manifest = new Manifest();
            _manifestHeader = new ManifestHeader
                {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographyScheme.Curve25519UM1Hybrid.ToString()
                };
            SetManifestCryptoCurve25519UM1(senderKey, receiverKey);
            LayoutScheme = layoutScheme;
        }


        #region Writing

        /// <summary>
		/// Add a text payload item (encoded in UTF-8) to the package with a relative path 
		/// of root (/) in the manifest. Default encryption is used.
		/// </summary>
		/// <param name="name">Name of the item. Subject of the text is suggested.</param>
		/// <param name="text">Content of the item.</param>
		/// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
		/// <exception cref="ArgumentException">Supplied null or empty string.</exception>
		public void AddText(string name, string text) {
            if (_reading) {
                throw new InvalidOperationException("Cannot modify state of the package.");
            }

			if(String.IsNullOrEmpty(name) || String.IsNullOrWhiteSpace(name)) {
				throw new ArgumentException ("Item name is null or empty string.");
			}
			var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));
			var newItem = CreateItem (() => stream, PayloadItemType.Utf8, stream.Length, name);

			_manifest.PayloadItems.Add(newItem);
		}

        /// <summary>
        /// Add a file-type payload item to the package with a relative path of root (/) in the manifest. 
        /// Default encryption is used.
        /// </summary>
        /// <param name="filePath">Path of the file to add.</param>
        /// <exception cref="FileNotFoundException">File does not exist.</exception>
        public void AddFile(string filePath) {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists) {
                throw new FileNotFoundException();
            }

			var newItem = CreateItem (fileInfo.OpenRead, PayloadItemType.Binary, fileInfo.Length, fileInfo.Name);
            _manifest.PayloadItems.Add(newItem);
        }

        /// <summary>
        /// Add a directory of files as payload items to the package with a relative path 
        /// of root (/) in the manifest. Default encryption is used.
        /// </summary>
        /// <param name="path">Path of the directory to search for and add files from.</param>
        /// <param name="search">Search for files in subdirectories (default) or not.</param>
        /// <exception cref="ArgumentException">Path supplied is not a directory.</exception>
        public void AddDirectory(string path, SearchOption search = SearchOption.AllDirectories) {
            var dir = new DirectoryInfo(path);

			if(Path.HasExtension(path)) {
				throw new ArgumentException ("Path is not a directory.");
			} else if (!dir.Exists) {
			    throw new DirectoryNotFoundException();
			}

            var rootPathLength = dir.FullName.Length;
            var files = dir.EnumerateFiles("*", search);
            foreach (var file in files) {
				var itemRelPath = search == SearchOption.TopDirectoryOnly
				                  ? file.Name : file.FullName.Remove(0, rootPathLength + 1);
				if (Path.DirectorySeparatorChar != Athena.Packaging.PathDirectorySeperator) {
					itemRelPath = itemRelPath.Replace(Path.DirectorySeparatorChar, Athena.Packaging.PathDirectorySeperator);
				}
				var newItem = CreateItem (file.OpenRead, PayloadItemType.Binary, file.Length, itemRelPath);

                _manifest.PayloadItems.Add(newItem);
            }
        }


		/// <summary>
		/// Creates a new PayloadItem DTO object, but does not add it to the manifest, returning it instead.
		/// </summary>
		/// <returns>A payload item.</returns>
		/// <remarks>Default encryption is AES-256/CTR with random IV and key.</remarks>
		/// <param name="itemData">Function supplying a stream of the item data.</param>
		/// <param name="itemType">Type of the item, e.g., Utf8 (text) or Binary (data/file).</param>
		/// <param name="externalLength">External length (outside the payload) of the item.</param>
		/// <param name="relativePath">Relative path of the item.</param>
		/// <param name="skipCrypto">
		/// If set to <c>true</c>, leaves Encryption property set to null - 
		/// for post-method-modification.
		/// </param>
		private static PayloadItem CreateItem(Func<Stream> itemData, PayloadItemType itemType, long externalLength, 
            string relativePath, bool skipCrypto = false)
        {
			var newItem = new PayloadItem {
				ExternalLength = externalLength,
				Type = itemType,
				RelativePath = relativePath,
				Encryption = !skipCrypto ? SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration
				             (SymmetricBlockCipher.Aes, BlockCipherMode.Ctr, BlockCipherPadding.None) : null
			};

			newItem.SetStreamBinding (itemData);
			return newItem;
		}

        /// <summary>
        /// Advanced method. Manually set a symmetric-only manifest cryptography configuration. 
        /// Misuse will likely result in unreadable package.
        /// </summary>
        /// <param name="configuration">Configuration to apply.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="ArgumentException">Object not a recognised type.</exception>
        /// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
        public void SetManifestCryptography(IManifestCryptographySchemeConfiguration configuration) {
            if (_reading) {
                throw new InvalidOperationException("Cannot change manifest cryptography of package being read.");
            }

            if (configuration is IDataTransferObject && (configuration is SymmetricManifestCryptographyConfiguration ||
                configuration is UM1ManifestCryptographyConfiguration || configuration is Curve25519UM1ManifestCryptographyConfiguration))
            {
                _manifestCryptoConfig = configuration;
            } else {
                throw new ArgumentException("Object is not a valid configuration within the ObscurCore package format specification.", "configuration");
            }
        }

        /// <summary>
        /// Set the manifest to use symmetric-only security.
        /// </summary>
        /// <param name="key">Key known to the receiver of the package.</param>
        /// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
        /// <exception cref="ArgumentException">Array is null or zero-length.</exception>
        public void SetManifestCryptoSymmetric(byte[] key) {
            if (_reading) {
                throw new InvalidOperationException("Cannot change manifest cryptography of package being read.");
            } else if (key.IsNullOrZeroLength()) {
                throw new ArgumentException("Key is null or zero-length.", "key");
            }

            if (_writingPreManifestKey != null) {
                Array.Clear(_writingPreManifestKey, 0, _writingPreManifestKey.Length);
            }

            _writingPreManifestKey = new byte[key.Length];
            Array.Copy(key, _writingPreManifestKey, key.Length);
            Debug.Print(DebugUtility.CreateReportString("Package", "SetManifestCryptoSymmetric", "Manifest pre-key",
                _writingPreManifestKey.ToHexString()));

            SymmetricCipherConfiguration cipherConfig = _manifestCryptoConfig == null
                ? CreateDefaultCipherConfiguration()
                : _manifestCryptoConfig.SymmetricCipher ?? CreateDefaultCipherConfiguration();
            KeyDerivationConfiguration derivationConfig =  _manifestCryptoConfig == null
                ? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8)
                : _manifestCryptoConfig.KeyDerivation ?? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8);
            _manifestCryptoConfig = new SymmetricManifestCryptographyConfiguration
                {
                    SymmetricCipher = cipherConfig,
                    KeyDerivation = derivationConfig,
                    KeyConfirmation = ConfirmationUtility.CreateDefaultManifestKeyConfirmation(_writingPreManifestKey)
                };
            _manifestHeader.CryptographySchemeName = ManifestCryptographyScheme.SymmetricOnly.ToString();
        }

        /// <summary>
        /// Set a specific block cipher configuration to be used for the cipher used for manifest encryption.
        /// </summary>
        /// <exception cref="InvalidOperationException">Package is being written, not read.</exception>
        /// <exception cref="ArgumentException">Enum was set to None.</exception>
        public void ConfigureManifestSymmetricCrypto(SymmetricBlockCipher cipher, BlockCipherMode mode, 
            BlockCipherPadding padding)
        {
            if (_reading) {
                throw new InvalidOperationException("Cannot change manifest cryptography of package being read.");
            }
            if (cipher == SymmetricBlockCipher.None) {
                throw new ArgumentException("Cipher cannot be set to none.", "cipher");
            } else if (mode == BlockCipherMode.None) {
                throw new ArgumentException("Mode cannot be set to none.", "mode");
            } else if (cipher == SymmetricBlockCipher.None) {
                throw new ArgumentException();
            }
            ManifestCipher = SymmetricCipherConfigurationFactory.CreateBlockCipherConfigurationWithoutKey(cipher, mode, padding);
        }

        /// <summary>
        /// Set a specific stream cipher to be used for the cipher used for manifest encryption.
        /// </summary>
        /// <exception cref="InvalidOperationException">Package is being written, not read.</exception>
        /// <exception cref="ArgumentException">Cipher was set to None.</exception>
        public void ConfigureManifestSymmetricCrypto(SymmetricStreamCipher cipher)
        {
            if (_reading) {
                throw new InvalidOperationException("Cannot change manifest cryptography of package being read.");
            }
            if (cipher == SymmetricStreamCipher.None) {
                throw new ArgumentException();
            }
            ManifestCipher = SymmetricCipherConfigurationFactory.CreateStreamCipherConfigurationWithoutKey(cipher);
        }

        /// <summary>
        /// Set manifest to use UM1-Hybrid cryptography.
        /// </summary>
        /// <param name="senderKey">Key of the sender (private key).</param>
        /// <param name="receiverKey">Key of the receiver (public key).</param>
        public void SetManifestCryptoUM1(EcKeyConfiguration senderKey, EcKeyConfiguration receiverKey) {
            if (_reading) {
                throw new InvalidOperationException("Cannot change manifest cryptography of package being read.");
            }

            var localPrivateKey = receiverKey.DecodeToPrivateKey();
            var remotePublicKey = senderKey.DecodeToPublicKey();

            ECPublicKeyParameters ephemeral;
            _writingPreManifestKey = UM1Exchange.Initiate(remotePublicKey, localPrivateKey, out ephemeral);
            Debug.Print(DebugUtility.CreateReportString("Package", "SetManifestCryptoUM1", "Manifest pre-key",
                _writingPreManifestKey.ToHexString()));

            SymmetricCipherConfiguration cipherConfig = _manifestCryptoConfig == null
                ? CreateDefaultCipherConfiguration()
                : _manifestCryptoConfig.SymmetricCipher ?? CreateDefaultCipherConfiguration();
            KeyDerivationConfiguration derivationConfig =  _manifestCryptoConfig == null
                ? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8)
                : _manifestCryptoConfig.KeyDerivation ?? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8);
            _manifestCryptoConfig = new UM1ManifestCryptographyConfiguration {
                    SymmetricCipher = cipherConfig,
                    KeyDerivation = derivationConfig,
                    KeyConfirmation = ConfirmationUtility.CreateDefaultManifestKeyConfirmation(_writingPreManifestKey),
                    EphemeralKey = new EcKeyConfiguration {
                            CurveProviderName = receiverKey.CurveProviderName,
                            CurveName = receiverKey.CurveName,
                            // Store the ephemeral public key in the manifest cryptography configuration
                            EncodedKey = ephemeral.Q.GetEncoded()
                        }
                };
            _manifestHeader.CryptographySchemeName = ManifestCryptographyScheme.UM1Hybrid.ToString();
        }

        /// <summary>
        /// Set manifest to use Curve25519-UM1-Hybrid cryptography.
        /// </summary>
        /// <param name="senderKey">Key of the sender (private key).</param>
        /// <param name="receiverKey">Key of the receiver (public key).</param>
        public void SetManifestCryptoCurve25519UM1(byte[] senderKey, byte[] receiverKey) {

            if (senderKey.Length != 32) {
                throw new ArgumentException(
                    "Sender's Curve25519 elliptic curve private key is not 32 bytes in length.", "senderKey");
            }
            if (receiverKey.Length != 32) {
                throw new ArgumentException(
                    "Recipient's Curve25519 elliptic curve public key is not 32 bytes in length.", "receiverKey");
            }

            byte[] ephemeralKey;
            _writingPreManifestKey = Curve25519UM1Exchange.Initiate(receiverKey, senderKey, out ephemeralKey);
            Debug.Print(DebugUtility.CreateReportString("Package", "SetManifestCryptoCurve25519UM1", "Manifest pre-key",
                _writingPreManifestKey.ToHexString()));

            SymmetricCipherConfiguration cipherConfig = _manifestCryptoConfig == null
                ? CreateDefaultCipherConfiguration()
                : _manifestCryptoConfig.SymmetricCipher ?? CreateDefaultCipherConfiguration();
            KeyDerivationConfiguration derivationConfig =  _manifestCryptoConfig == null
                ? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8)
                : _manifestCryptoConfig.KeyDerivation ?? CreateDefaultManifestKeyDerivation(cipherConfig.KeySizeBits / 8);
            _manifestCryptoConfig = new Curve25519UM1ManifestCryptographyConfiguration {
                    SymmetricCipher = cipherConfig,
                    KeyDerivation = derivationConfig,
                    KeyConfirmation = ConfirmationUtility.CreateDefaultManifestKeyConfirmation(_writingPreManifestKey),
                    EphemeralKey = ephemeralKey
                };
            _manifestHeader.CryptographySchemeName = ManifestCryptographyScheme.Curve25519UM1Hybrid.ToString();
        }

        private static SymmetricCipherConfiguration CreateDefaultCipherConfiguration() {
            return SymmetricCipherConfigurationFactory.CreateBlockCipherConfigurationWithoutKey(
                SymmetricBlockCipher.Aes, BlockCipherMode.Ctr, BlockCipherPadding.None);
        }

		/// <summary>
		/// Creates a default manifest key derivation configuration.
		/// </summary>
		/// <remarks>Default KDF configuration is scrypt</remarks>
		/// <returns>Key derivation configuration.</returns>
		/// <param name="keyLengthBytes">Length of key to produce.</param>
		private static KeyDerivationConfiguration CreateDefaultManifestKeyDerivation(int keyLengthBytes) {
			var schemeConfig = new ScryptConfiguration {
				IterationPower = 16,
				Blocks = 8,
				Parallelism = 2
			};
			var config = new KeyDerivationConfiguration {
				SchemeName = KeyDerivationFunction.Scrypt.ToString(),
				SchemeConfiguration = schemeConfig.SerialiseDto(),
				Salt = new byte[keyLengthBytes]
			};
			StratCom.EntropySource.NextBytes(config.Salt);
			return config;
		}

        
        /// <summary>
        /// Write package out to bound stream.
        /// </summary>
        /// <param name="outputStream">Stream which the package is to be written to.</param>
        /// <param name="closeOnComplete">Whether to close the destination stream upon completion of writing.</param>
        /// <exception cref="AggregateException">
        /// <para>Collection of however many items have no stream bindings as <see cref="ItemStreamBindingAbsentException"/></para>
        /// <para>or</para>
        /// <para>Collection of however many items have no cipher keys as <see cref="ItemStreamBindingAbsentException"/></para>
        /// </exception>
        public void Write(Stream outputStream, bool closeOnComplete = true) {
            // Sanity checks
            if (_writingComplete) {
                throw new NotSupportedException("Multiple writes from one package are not supported; it may compromise security properties.");
            }
            if (_manifestCryptoConfig == null) {
                throw new InvalidOperationException("Manifest cryptography scheme and its configuration is not set up.");
            }

            if (_manifest.PayloadItems.Count == 0) {
                throw new InvalidOperationException("No payload items have been added.");
            }
            if (_manifest.PayloadItems.Any(item => !item.StreamHasBinding)) {
                throw new AggregateException(
                    _manifest.PayloadItems.Where(payloadItem => !payloadItem.StreamHasBinding)
                             .Select(payloadItem => new ItemStreamBindingAbsentException(payloadItem)));
            }
            if (_manifest.PayloadItems.Any(item => item.Encryption.Key.IsNullOrZeroLength())) {
                throw new AggregateException(
                    _manifest.PayloadItems.Where(payloadItem => payloadItem.Encryption.Key.IsNullOrZeroLength())
                             .Select(payloadItem => new ItemKeyMissingException(payloadItem)));
            }

            if (!outputStream.CanWrite) throw new IOException("Cannot write to output stream.");
            if (_writingTempStream == null) {
                // Default to writing to memory
                _writingTempStream = new MemoryStream();
            }

            // Serialise the manifest crypto configuration
            switch (ManifestCryptoScheme) {
                case ManifestCryptographyScheme.SymmetricOnly:
                    _manifestHeader.CryptographySchemeConfiguration =
                        ((SymmetricManifestCryptographyConfiguration) _manifestCryptoConfig).SerialiseDto();
                    break;
                case ManifestCryptographyScheme.UM1Hybrid:
                    _manifestHeader.CryptographySchemeConfiguration =
                        ((UM1ManifestCryptographyConfiguration) _manifestCryptoConfig).SerialiseDto();
                    break;
                case ManifestCryptographyScheme.Curve25519UM1Hybrid:
                    _manifestHeader.CryptographySchemeConfiguration =
                        ((Curve25519UM1ManifestCryptographyConfiguration) _manifestCryptoConfig).SerialiseDto();
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
            
            // Derive the key which will be used for encrypting the manifest
            var workingMKey = Source.DeriveKeyWithKdf(_manifestCryptoConfig.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunction>(),
                _writingPreManifestKey, _manifestCryptoConfig.KeyDerivation.Salt, _manifestCryptoConfig.SymmetricCipher.KeySizeBits,
                _manifestCryptoConfig.KeyDerivation.SchemeConfiguration);
            
            // Clear the pre-key from memory
            Array.Clear(_writingPreManifestKey, 0, _writingPreManifestKey.Length);

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest working key",
                workingMKey.ToHexString()));
            
            /* Now we write the package */
            
            // Write the header tag
            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "[*PACKAGE START*] Header offset (absolute)",
                outputStream.Position));
            var headerTag = Athena.Packaging.GetHeaderTag();
            outputStream.Write(headerTag, 0, headerTag.Length);

            // Serialise and write ManifestHeader (this part is written as plaintext, otherwise INCEPTION!)
            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest header offset (absolute)",
                outputStream.Position));
            _manifestHeader.SerialiseDto(outputStream, prefixLength: true);

            /* Prepare for writing payload */

            // Create and bind transform functions (compression, encryption, etc) defined by items' configurations to those items
            var transformFunctions = _manifest.PayloadItems.Select(item => (Func<Stream, DecoratingStream>) (binding =>
                item.BindTransformStream(true, binding))).ToList();

            /* Write the payload to temporary storage (payloadTemp) */
            PayloadLayoutScheme payloadScheme;
            try {
                payloadScheme = _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>();
            } catch (Exception) {
                throw new PackageConfigurationException(
                    "Package payload schema specified is unsupported/unknown or missing.");
            }
            // Bind the multiplexer to the temp stream
            var mux = Source.CreatePayloadMultiplexer(payloadScheme, true, _writingTempStream,
                _manifest.PayloadItems.ToList<IStreamBinding>(),
                transformFunctions, _manifest.PayloadConfiguration);

            try {
                mux.ExecuteAll();
            } catch (Exception e) {
                throw;
            }

            // Get internal lengths of the written items from the muxer and commit them to the manifest
	        for (var i = 0; i < _manifest.PayloadItems.Count; i++) {
	            _manifest.PayloadItems[i].InternalLength = mux.GetItemIO(i, source: false);
	        }

            /* Write the manifest in encrypted form */
            using (var manifestTemp = new MemoryStream()) {
                using (var cs = new SymmetricCryptoStream(manifestTemp, true, _manifestCryptoConfig.SymmetricCipher, workingMKey, false)) {
                    _manifest.SerialiseDto(cs);
                }
                // Write length prefix
                Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest length prefix offset (absolute)",
                    outputStream.Position));
                outputStream.WritePrimitive((UInt32)manifestTemp.Length); // Manifest length is written as uint32

                Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest offset (absolute)",
                    outputStream.Position));

                manifestTemp.WriteTo(outputStream);
            }

            // Clear manifest key from memory
            Array.Clear(workingMKey, 0, workingMKey.Length);

            // Write payload offset filler, where applicable
            if (_manifest.PayloadConfiguration.Offset > 0) {
                var paddingBytes = new byte[_manifest.PayloadConfiguration.Offset];
                StratCom.EntropySource.NextBytes(paddingBytes);
                outputStream.Write(paddingBytes, 0, paddingBytes.Length);
            }

            /* Write out payloadTemp to output stream */
            _readingPayloadStreamOffset = outputStream.Position;
            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Payload offset (absolute)",
                    _readingPayloadStreamOffset));
            _writingTempStream.Seek(0, SeekOrigin.Begin);
            _writingTempStream.CopyTo(outputStream);

            // Write the trailer tag
            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Trailer offset (absolute)",
                    outputStream.Position));
            var trailerTag = Athena.Packaging.GetTrailerTag();
            outputStream.Write(trailerTag, 0, trailerTag.Length);

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "[* PACKAGE END *] Offset (absolute)",
                    outputStream.Position));

            // All done! HAPPY DAYS.
            _writingTempStream.Close();
            _writingTempStream = null;
            if(closeOnComplete) outputStream.Close();
            _writingComplete = true;
        }

        /// <summary>
        /// Set the location of temporary data written during the write process. 
        /// </summary>
        /// <param name="stream">Stream to use for temporary storage.</param>
        public void SetTemporaryStorageStream(Stream stream) {
            if (stream == null || stream == Stream.Null) {
                throw new ArgumentException("Stream is null or points toward oblivion.");
            } else if (_reading) {
                throw new InvalidOperationException("Method is not applicable to package reads.");
            }
            _writingTempStream = stream;
        }

        #endregion


        #region Reading

        /// <summary>
        /// Read a package from a file.
        /// </summary>
        /// <returns>Package ready for reading.</returns>
        /// <exception cref="ArgumentException">File does not exist at the path specified.</exception>
		public static Package FromFile(string filePath, IKeyProvider keyProvider) {
            var file = new FileInfo(filePath);
            if(!file.Exists) throw new ArgumentException();
            return FromStream(file.OpenRead(), keyProvider);
        }

        /// <summary>
        /// Read a package from a stream.
        /// </summary>
        /// <returns>Package ready for reading.</returns>
        public static Package FromStream(Stream stream, IKeyProvider keyProvider) {
            var package = new Package(stream, keyProvider);
            return package;
        }

        /// <summary>
        /// Constructor for static-origin inits (reads). 
        /// Immediately reads package manifest header and manifest.
        /// </summary>
        internal Package(Stream stream, IKeyProvider keyProvider) {
            _readingStream = stream;
            _reading = true;
            ManifestCryptographyScheme mCryptoScheme;

            _manifestHeader = ReadManifestHeader(_readingStream, out _manifestCryptoConfig, out mCryptoScheme);
            _manifest = ReadManifest(keyProvider, mCryptoScheme);
        }


        /// <summary>
        /// Reads a package manifest header (only) from a stream.
        /// </summary>
        /// <param name="sourceStream">Stream to read the header from.</param>
        /// <param name="cryptoConfig">Manifest cryptography configuration deserialised from the header.</param>
        /// <param name="mCryptoScheme">Manifest cryptography scheme parsed from the header.</param>
        /// <returns>Package manifest header object.</returns>
        /// <exception cref="InvalidDataException">Package data structure is malformed.</exception>
        /// <exception cref="NotSupportedException">Version format specified is unknown to the local version.</exception>
        private static ManifestHeader ReadManifestHeader(Stream sourceStream, out IManifestCryptographySchemeConfiguration cryptoConfig,
			out ManifestCryptographyScheme mCryptoScheme)
        {
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifestHeader", "[* PACKAGE START* ] Header offset (absolute)",
				sourceStream.Position));

			var referenceHeaderTag = Athena.Packaging.GetHeaderTag();
			var readHeaderTag = new byte[referenceHeaderTag.Length];
			sourceStream.Read(readHeaderTag, 0, readHeaderTag.Length);
			if (!readHeaderTag.SequenceEqual(referenceHeaderTag)) {
				throw new InvalidDataException("Package is malformed. Expected header tag is either absent or malformed.");
			}

			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifestHeader", "Manifest header offset (absolute)",
				sourceStream.Position));

            var manifestHeader = StratCom.DeserialiseDataTransferObject<ManifestHeader>(sourceStream);

			if (manifestHeader.FormatVersion > Athena.Packaging.HeaderVersion) {
				throw new NotSupportedException(String.Format("Package version {0} as specified by the manifest header is unsupported/unknown.\n" +
					"The local version of ObscurCore supports up to version {1}.", manifestHeader.FormatVersion, Athena.Packaging.HeaderVersion));
				// In later versions, can redirect to diff. behaviour (and DTO objects) for diff. versions.
			}

			mCryptoScheme = manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>();
			switch (manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>()) {
			case ManifestCryptographyScheme.SymmetricOnly:
                cryptoConfig = StratCom.DeserialiseDataTransferObject<SymmetricManifestCryptographyConfiguration>
                    (manifestHeader.CryptographySchemeConfiguration);
				break;
			case ManifestCryptographyScheme.UM1Hybrid:
                cryptoConfig = StratCom.DeserialiseDataTransferObject<UM1ManifestCryptographyConfiguration>
                    (manifestHeader.CryptographySchemeConfiguration);
				break;
			case ManifestCryptographyScheme.Curve25519UM1Hybrid:
                cryptoConfig = StratCom.DeserialiseDataTransferObject<Curve25519UM1ManifestCryptographyConfiguration>
                    (manifestHeader.CryptographySchemeConfiguration);
				break;
			default:
				throw new NotSupportedException(String.Format(
					"Package manifest cryptography scheme \"{0}\" as specified by the manifest header is unsupported/unknown.", 
					manifestHeader.CryptographySchemeName));
			}

			return manifestHeader;
		}

        /// <summary>
        /// Read manifest from package.
        /// </summary>
        /// <remarks>
        /// Call method, supplying (all of) only the keys associated with the sender and the context. 
        /// This maximises the chance that 1) the package will be successfully decrypted if multiple 
        /// keys are in use by both parties, and 2) minimises the time spent validating potential key pairs.
        /// </remarks>
        /// <param name="keyProvider">Provider to get possible keys for the manifest from.</param>
        /// <param name="manifestScheme">Cryptography scheme used in the manifest.</param>
        /// <returns>Package manifest object.</returns>
        /// <exception cref="ArgumentException">Key provider absent or did not supply any keys.</exception>
        /// <exception cref="NotSupportedException">Manifest cryptography scheme unsupported/unknown or missing.</exception>
        /// <exception cref="KeyConfirmationException">Key confirmation failed to determine a key, or failed unexpectedly.</exception>
        /// <exception cref="InvalidDataException">Deserialisation of manifest failed unexpectedly.</exception>
        private Manifest ReadManifest(IKeyProvider keyProvider, ManifestCryptographyScheme manifestScheme) {
            // Determine the pre-key for the package manifest decryption (different schemes use different approaches)
            byte[] preMKey;
            switch (manifestScheme) {
                case ManifestCryptographyScheme.SymmetricOnly:
                    if (!keyProvider.SymmetricKeys.Any()) {
                        throw new ArgumentException("No symmetric keys available for decryption of this manifest.", 
                            "keyProvider");
                    }
                    if (_manifestCryptoConfig.KeyConfirmation != null) {
                        try {
                            preMKey = ConfirmationUtility.ConfirmSymmetricKey(
                                ((SymmetricManifestCryptographyConfiguration) _manifestCryptoConfig).KeyConfirmation,
                                keyProvider.SymmetricKeys);
                        } catch (Exception e) {
                            throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                        }
                    } else {
                        if (keyProvider.SymmetricKeys.Any()) {
                            // Possibly allow to proceed anyway and just look for a serialisation failure? (not implemented)
                            throw new ArgumentException("Multiple symmetric keys are available, but this package provides no key confirmation capability.", 
                                "keyProvider");
                        }
                        preMKey = keyProvider.SymmetricKeys.First();
                    }
                    break;
                case ManifestCryptographyScheme.UM1Hybrid:
                    // Identify matching public-private key pairs based on curve provider and curve name
                    var um1EphemeralKey = ((UM1ManifestCryptographyConfiguration) _manifestCryptoConfig).EphemeralKey;
                
                    if (_manifestCryptoConfig.KeyConfirmation != null) {
                        try {
                            preMKey = ConfirmationUtility.ConfirmUM1HybridKey(_manifestCryptoConfig.KeyConfirmation,
                                um1EphemeralKey, keyProvider.EcSenderKeys, keyProvider.EcReceiverKeys);
                        } catch (Exception e) {
                            throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                        }
                    } else {
						// No key confirmation capability available
						if (keyProvider.EcSenderKeys.Any() || keyProvider.EcReceiverKeys.Any()) {
							throw new KeyConfirmationException("Multiple EC keys have been provided where the package provides no key confirmation capability.");
						}
                        preMKey = UM1Exchange.Respond(keyProvider.EcSenderKeys.First().DecodeToPublicKey(),
                            keyProvider.EcReceiverKeys.First().DecodeToPrivateKey(),
                            um1EphemeralKey.DecodeToPublicKey());
                    }
                    break;
                case ManifestCryptographyScheme.Curve25519UM1Hybrid:
                    var c25519Um1EphemeralKey = ((Curve25519UM1ManifestCryptographyConfiguration) _manifestCryptoConfig).EphemeralKey;
                    if (_manifestCryptoConfig.KeyConfirmation != null) {
                        preMKey = ConfirmationUtility.ConfirmCurve25519UM1HybridKey(_manifestCryptoConfig.KeyConfirmation,
                            c25519Um1EphemeralKey, keyProvider.Curve25519SenderKeys, keyProvider.Curve25519ReceiverKeys);
                    } else {
						// No key confirmation capability available
						if (keyProvider.Curve25519SenderKeys.Any() || keyProvider.Curve25519ReceiverKeys.Any()) {
							throw new KeyConfirmationException("Multiple Curve25519 keys have been provided where the package provides no key confirmation capability.");
						}
						preMKey = Curve25519UM1Exchange.Respond(keyProvider.Curve25519SenderKeys.First(), keyProvider.Curve25519ReceiverKeys.First(), 
                            c25519Um1EphemeralKey);
					}
                    break;
                default:
                    throw new NotSupportedException(String.Format("Manifest cryptography scheme \"{0}\" is unsupported/unknown.", manifestScheme));
            }

            if (preMKey == null || preMKey.Length == 0) {
                throw new KeyConfirmationException(String.Format(
                    "None of the keys provided to decrypt the manifest (cryptographic scheme: {0}) were confirmed as being able to do so.", manifestScheme));
            }

            Debug.Print(DebugUtility.CreateReportString("Package", "ReadManifest", "Manifest pre-key",
                    preMKey.ToHexString()));

            // Derive the manifest working key
            var workingMKey = Source.DeriveKeyWithKdf(_manifestCryptoConfig.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunction>(),
                    preMKey, _manifestCryptoConfig.KeyDerivation.Salt, _manifestCryptoConfig.SymmetricCipher.KeySizeBits,
                    _manifestCryptoConfig.KeyDerivation.SchemeConfiguration);

            // Clear the manifest pre-key
            Array.Clear(preMKey, 0, preMKey.Length);

            Debug.Print(DebugUtility.CreateReportString("Package", "ReadManifest", "Manifest working key",
                    workingMKey.ToHexString()));
            Debug.Print(DebugUtility.CreateReportString("Package", "ReadManifest", "Manifest length prefix offset (absolute)",
                    _readingStream.Position));

            // Read manifest length prefix
            Manifest manifest;
            uint mlUint;
            _readingStream.ReadPrimitive(out mlUint);
            var manifestLength = (int) mlUint;

            Debug.Print(DebugUtility.CreateReportString("Package", "ReadManifest", "Manifest length prefix",
                    manifestLength));
            Debug.Print(DebugUtility.CreateReportString("Package", "ReadManifest", "Manifest offset (absolute)",
                    _readingStream.Position));

            /* Read manifest */
            using (var decryptedManifestStream = new MemoryStream()) {
                using (var encryptedManifestStream = new MemoryStream()) {
                    const int bufferLength = 4096;
                    var readBuffer = new byte[bufferLength];
                    while (manifestLength > 0) {
                        var count = _readingStream.Read(readBuffer, 0, Math.Min(manifestLength, bufferLength));
                        manifestLength -= count;
                        encryptedManifestStream.Write(readBuffer, 0, count);
                    }
                    encryptedManifestStream.Seek(0, SeekOrigin.Begin);
                    // Decrypt the manifest from the MemoryStream buffer (prevents protobuf-net overread)
                    using (var cs = new SymmetricCryptoStream(encryptedManifestStream, false, _manifestCryptoConfig.SymmetricCipher, workingMKey, false)) {
                        cs.CopyTo(decryptedManifestStream);
                    }
                    // Clear the manifest working key
                    Array.Clear(workingMKey, 0, workingMKey.Length);
                }
                decryptedManifestStream.Seek(0, SeekOrigin.Begin);
                try {
                    manifest = (Manifest)StratCom.Serialiser.Deserialize(decryptedManifestStream, null, typeof (Manifest));
                } catch (Exception e) {
                    throw new InvalidDataException("Manifest failed to deserialise.");
                }
            }
            
            return manifest;
        }

        /// <summary>
        /// Performs key confirmation and derivation on each payload item.
        /// </summary>
        /// <param name="payloadKeysSymmetric">Potential symmetric keys for payload items.</param>
        /// <exception cref="AggregateException">
        /// Consisting of ItemKeyMissingException, indicating items missing cryptographic keys.
        /// </exception>
        public void ConfirmAndDeriveItemKeys(IEnumerable<byte[]> payloadKeysSymmetric = null) {
            if (!_reading) {
                throw new InvalidOperationException("Not reading a package.");
            }

            var keys = payloadKeysSymmetric != null ? payloadKeysSymmetric.ToList() : new List<byte[]>();
            var errorList = new List<PayloadItem>();
			foreach (var item in _manifest.PayloadItems.Where(item => item.Encryption.Key.IsNullOrZeroLength())) {
			    if(item.KeyConfirmation == null) {
                    errorList.Add(item);
			    }
			    // We will derive the key from one supplied as a potential
			    var preIKey = ConfirmationUtility.ConfirmSymmetricKey(item.KeyConfirmation, keys);
			    if (preIKey == null || preIKey.Length == 0) {
			        errorList.Add(item);
			    }
                if (errorList.Count == 0) {
                    item.Encryption.Key = Source.DeriveKeyWithKdf(item.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunction>(),
			        preIKey, item.KeyDerivation.Salt, item.Encryption.KeySizeBits,
			        item.KeyDerivation.SchemeConfiguration);
                }
			}
            if (errorList.Count > 0) {
                throw new AggregateException(errorList.Select(item => new ItemKeyMissingException(item)));
            }
        }

        private static void CheckItemPathSafety(IEnumerable<PayloadItem> items) {
            var relUp = ".." + Path.DirectorySeparatorChar;
            if (items.Where(item => item.Type != PayloadItemType.KeyAction).Any(item => item.RelativePath.Contains(relUp))) {
                throw new InvalidDataException("A payload item specifies a relative path outside that of the package root. " 
                    + " This is a potentially dangerous condition.");
            }
        }

        /// <summary>
        /// Read a package into a directory. Just like extracting an archive.
        /// </summary>
        /// <param name="path">Path to write items to.</param>
        /// <param name="payloadKeys">Potential symmetric keys for payload items.</param>
        /// <exception cref="InvalidOperationException">Package is being written, not read.</exception>
        /// <exception cref="NotImplementedException">Package includes a KeyAction payload item type (not implemented).</exception>
        public void ReadToDirectory(string path, IEnumerable<byte[]> payloadKeys = null) {
            if (!_reading) {
                throw new InvalidOperationException("Not reading a package.");
            }

            var directory = new DirectoryInfo(path);
            if(!directory.Exists) directory.Create();
            CheckItemPathSafety(_manifest.PayloadItems);

            foreach (var item in _manifest.PayloadItems) {
                var relativePath = item.RelativePath.Insert(0, path + Path.DirectorySeparatorChar)
                    .Replace(Athena.Packaging.PathDirectorySeperator, Path.DirectorySeparatorChar);
                switch (item.Type) {
                    case PayloadItemType.Utf8:
                    case PayloadItemType.Utf32:
                        relativePath = item.RelativePath.Insert(0, path + Path.DirectorySeparatorChar)
                            .Replace(Athena.Packaging.PathDirectorySeperator, Path.DirectorySeparatorChar);
                        relativePath += ".txt";
                        break;
                    case PayloadItemType.KeyAction:
                        throw new NotImplementedException();
                }
                item.SetStreamBinding(() => new FileStream(relativePath, FileMode.Create));
            }
            ReadPayload(payloadKeys);
        }

        /// <summary>
        /// Read payload from package.
        /// </summary>
        /// <param name="payloadKeys">Potential keys for payload items.</param>
        /// <exception cref="PackageConfigurationException">Payload layout scheme malformed/missing.</exception>
        /// <exception cref="InvalidDataException">Package data structure malformed.</exception>
        private void ReadPayload(IEnumerable<byte[]> payloadKeys = null) {
            if (_readingPayloadStreamOffset != 0 && _readingStream.Position != _readingPayloadStreamOffset) {
                _readingStream.Seek(_readingPayloadStreamOffset, SeekOrigin.Begin);
            } else {
                if (_manifest.PayloadConfiguration.Offset > 0) {
                    _readingStream.Seek (_manifest.PayloadConfiguration.Offset, SeekOrigin.Current);
                    _readingPayloadStreamOffset = _readingStream.Position;
                }
            }

            Debug.Print(DebugUtility.CreateReportString("Package", "Read", "Payload offset (absolute)",
                    _readingStream.Position));

			// Check that all payload items have decryption keys - if they do not, confirm them from potentials
			ConfirmAndDeriveItemKeys(payloadKeys);

			// Create and bind transform functions (compression, encryption, etc) defined by items' configurations to those items
			var transformFunctions = _manifest.PayloadItems.Select(item => (Func<Stream, DecoratingStream>) 
				(binding => item.BindTransformStream(false, binding))).ToList();

			// Read the payload
			PayloadLayoutScheme payloadScheme;
			try {
				payloadScheme = _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme> ();
			} catch (Exception) {
				throw new PackageConfigurationException("Payload layout scheme specified is unsupported/unknown or missing.");
			}
			var mux = Source.CreatePayloadMultiplexer(payloadScheme, false, _readingStream, _manifest.PayloadItems.ToList<IStreamBinding>(), 
			                                          transformFunctions, _manifest.PayloadConfiguration);

			// Demux the payload
			try {
				mux.ExecuteAll ();
			} catch (Exception ex) {
				// Catch different kinds of exception in future
				throw;
			}

            Debug.Print(DebugUtility.CreateReportString("Package", "ReadPayload", "Trailer offset (absolute)",
                    _readingStream.Position));

			// Read the trailer
            var referenceHeaderTag = Athena.Packaging.GetTrailerTag();
			var readTrailerTag = new byte[referenceHeaderTag.Length];
			_readingStream.Read (readTrailerTag, 0, readTrailerTag.Length);
			if(!readTrailerTag.SequenceEqual(referenceHeaderTag)) {
				throw new InvalidDataException("Package is malformed. Trailer tag is either absent or malformed." 
				                               + "It would appear, however, that the package has unpacked successfully despite this.");
			}

            Debug.Print(DebugUtility.CreateReportString("Package", "ReadPayload", "[* PACKAGE END *] Offset (absolute)",
                    _readingStream.Position));
        }

        #endregion

    }
}
