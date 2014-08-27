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
using System.Threading.Tasks;
using LZ4PCL;
using Nessos.LinqOptimizer.CSharp;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyConfirmation;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore
{
    /// <summary>
    ///     Reads and extracts ObscurCore packages.
    /// </summary>
    public sealed class PackageReader : IDisposable
    {
        #region Instance variables

        private readonly Dictionary<Guid, byte[]> _itemPreKeys = new Dictionary<Guid, byte[]>();
        private readonly Manifest _manifest;

        /// <summary>
        ///     Configuration of the manifest cipher. Must be serialised into ManifestHeader when writing package.
        /// </summary>
        private readonly IManifestCryptographySchemeConfiguration _manifestCryptoConfig;

        private readonly ManifestHeader _manifestHeader;

        /// <summary>
        ///     Stream that package is being read from.
        /// </summary>
        private readonly Stream _readingStream;

        /// <summary>
        ///     Offset at which the payload starts.
        /// </summary>
        private long _readingPayloadStreamOffset;

        private bool _closeOnDispose;

        #endregion

        #region Properties

        /// <summary>
        ///     Format version specification of the data transfer objects and logic used in the package.
        /// </summary>
        public int FormatVersion
        {
            get { return _manifestHeader.FormatVersion; }
        }

        /// <summary>
        ///     Cryptographic scheme used for the manifest.
        /// </summary>
        public ManifestCryptographyScheme ManifestCryptoScheme
        {
            get { return _manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>(); }
        }

        /// <summary>
        ///     Configuration of symmetric cipher used for encryption of the manifest.
        /// </summary>
        public ICipherConfiguration ManifestCipher
        {
            get { return _manifestCryptoConfig.SymmetricCipher; }
        }

        /// <summary>
        ///     Configuration of function used in verifying the authenticity/integrity of the manifest.
        /// </summary>
        public IAuthenticationFunctionConfiguration ManifestAuthentication
        {
            get { return _manifestCryptoConfig.Authentication; }
        }

        /// <summary>
        ///     Configuration of key derivation used to derive encryption and authentication keys from prior key material.
        ///     These keys are used in those functions of manifest encryption/authentication, respectively.
        /// </summary>
        public IKeyDerivationConfiguration ManifestKeyDerivation
        {
            get { return _manifestCryptoConfig.KeyDerivation; }
        }

        /// <summary>
        ///     Configuration of key confirmation used for confirming the cryptographic key
        ///     to be used as the basis for key derivation.
        /// </summary>
        public IAuthenticationFunctionConfiguration ManifestKeyConfirmation
        {
            get { return _manifestCryptoConfig.KeyConfirmation; }
        }

        /// <summary>
        ///     Layout scheme configuration of the items in the payload.
        /// </summary>
        public PayloadLayoutScheme PayloadLayout
        {
            get { return _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>(); }
        }

        /// <summary>
        ///     Items in the package payload.
        /// </summary>
        public IEnumerable<IPayloadItem> PayloadItems
        {
            get { return _manifest.PayloadItems.Select(item => item as IPayloadItem); }
        }

        #endregion

        #region Constructors (including static methods that return a PackageReader)

        /// <summary>
        ///     Creates a package reader configured to read from a provided stream (containing the package).
        /// </summary>
        /// <remarks>
        ///     Immediately reads package manifest header and manifest.
        /// </remarks>
        /// <param name="stream">Stream to read the package from.</param>
        /// <param name="keyProvider">Service that supplies possible cryptographic keys.</param>
        /// <param name="closeOnDispose">
        ///     If <c>true</c>, <paramref name="stream"/> will be closed when the reader is disposed.
        /// </param>
        internal PackageReader(Stream stream, IKeyProvider keyProvider, bool closeOnDispose = false)
        {
            _readingStream = stream;
            _closeOnDispose = closeOnDispose;
            ManifestCryptographyScheme mCryptoScheme;

            _manifestHeader = ReadManifestHeader(_readingStream, out mCryptoScheme, out _manifestCryptoConfig);
            _manifest = ReadManifest(keyProvider, mCryptoScheme);
        }

        /// <summary>
        ///     Creates a package reader configured to read from a file.
        /// </summary>
        /// <param name="filePath">Path of the file containing a package.</param>
        /// <param name="keyProvider">Service that supplies possible cryptographic keys.</param>
        /// <returns>Package ready for reading.</returns>
        /// <exception cref="ArgumentException">File does not exist at the path specified.</exception>
        public static PackageReader FromFile(string filePath, IKeyProvider keyProvider)
        {
            var file = new FileInfo(filePath);
            if (file.Exists == false) {
                throw new ArgumentException();
            }
            return FromStream(file.OpenRead(), keyProvider);
        }

        /// <summary>
        ///     Creates a package reader configured to read from a provided stream (containing the package).
        /// </summary>
        /// <remarks>
        ///     Immediately reads package manifest header and manifest.
        /// </remarks>
        /// <param name="stream">Stream to read the package from.</param>
        /// <param name="keyProvider">Service that supplies possible cryptographic keys.</param>
        /// <returns>Package ready for reading.</returns>
        public static PackageReader FromStream(Stream stream, IKeyProvider keyProvider)
        {
            return new PackageReader(stream, keyProvider);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Exposes the payload items in the manifest as a tree, to facilitate treating it as a filesystem.
        /// </summary>
        public PayloadTree InspectPayloadAsFilesystem()
        {
            var tree = new PayloadTree();
            foreach (var payloadItem in _manifest.PayloadItems) {
                tree.AddItem(payloadItem, payloadItem.Path);
            }
            return tree;
        } 

        /// <summary>
        ///     Performs key confirmation and derivation on each payload item.
        /// </summary>
        /// <param name="payloadKeysSymmetric">Potential symmetric keys for payload items.</param>
        /// <exception cref="AggregateException">
        ///     Consisting of ItemKeyMissingException, indicating items missing cryptographic keys.
        /// </exception>
        private void ConfirmItemPreKeys(IEnumerable<SymmetricKey> payloadKeysSymmetric = null)
        {
            var keys = payloadKeysSymmetric != null ? payloadKeysSymmetric.ToList() : new List<SymmetricKey>();
            var keylessItems = new List<PayloadItem>();

            IEnumerable<PayloadItem> itemsToConfirm = _manifest.PayloadItems.AsQueryExpr()
                .Where(item => 
                    item.SymmetricCipherKey.IsNullOrZeroLength() || 
                    item.AuthenticationKey.IsNullOrZeroLength())
                .Run();

            Parallel.ForEach(itemsToConfirm, item => {
                if (item.KeyConfirmation != null && item.KeyDerivation != null) {
                    // We will derive the key from one supplied as a potential
                    SymmetricKey symmetricKey;
                    try {
                        symmetricKey = ConfirmationUtility.ConfirmKeyFromCanary(
                            ((SymmetricManifestCryptographyConfiguration)_manifestCryptoConfig).KeyConfirmation,
                            _manifestCryptoConfig.KeyConfirmationVerifiedOutput, keys);
                    } catch (Exception e) {
                        throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                    }
                    if (symmetricKey != null) {
                        if (symmetricKey.Key.IsNullOrZeroLength()) {
                            throw new ArgumentException("Supplied symmetric key is null or zero-length.",
                                "payloadKeysSymmetric");
                        }
                        _itemPreKeys.Add(item.Identifier, symmetricKey.Key);
                    } else {
                        keylessItems.Add(item);
                    }
                } else {
                    keylessItems.Add(item);
                }
            });

            if (keylessItems.Count > 0) {
                throw new AggregateException(keylessItems.Select(item => new ItemKeyMissingException(item)));
            }
        }

        #endregion

        /// <summary>
        ///     Reads a package manifest header from a stream.
        /// </summary>
        /// <param name="sourceStream">Stream to read the header from.</param>
        /// <param name="cryptoScheme">Manifest cryptography scheme parsed from the header.</param>
        /// <param name="cryptoConfig">Manifest cryptography configuration deserialised from the header.</param>
        /// <returns>Package manifest header.</returns>
        /// <exception cref="DataLengthException">End of stream encountered unexpectedly (contents truncated).</exception>
        /// <exception cref="InvalidDataException">Package data structure is out of specification or otherwise malformed.</exception>
        /// <exception cref="NotSupportedException">Version format specified is unknown to the local version.</exception>
        private static ManifestHeader ReadManifestHeader(Stream sourceStream,
            out ManifestCryptographyScheme cryptoScheme,
            out IManifestCryptographySchemeConfiguration cryptoConfig)
        {
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifestHeader",
                "[* PACKAGE START* ] Header offset (absolute)",
                sourceStream.Position));

            byte[] referenceHeaderTag = Athena.Packaging.GetPackageHeaderTag();
            var readHeaderTag = new byte[referenceHeaderTag.Length];
            int headerTagBytesRead = sourceStream.Read(readHeaderTag, 0, readHeaderTag.Length);
            if (readHeaderTag.SequenceEqualShortCircuiting(referenceHeaderTag) == false) {
                if (headerTagBytesRead != referenceHeaderTag.Length) {
                    throw new DataLengthException("Insufficient data to read package header tag.");
                }
                throw new InvalidDataException(
                    "Package is malformed. Expected header tag is either absent or malformed.");
            }

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifestHeader",
                "Manifest header offset (absolute)",
                sourceStream.Position));

            var manifestHeader = StratCom.DeserialiseDataTransferObject<ManifestHeader>(sourceStream, true);

            if (manifestHeader.FormatVersion <= 0) {
                throw new InvalidDataException("Package format descriptor is 0 or less (must be 1 or more).");
            }
            if (manifestHeader.FormatVersion > Athena.Packaging.PackageFormatVersion) {
                throw new NotSupportedException(
                    String.Format("Package version {0} as specified by the manifest header is unsupported/unknown.\n" +
                                  "The local version of ObscurCore supports up to version {1}.",
                        manifestHeader.FormatVersion, Athena.Packaging.PackageFormatVersion));
                // In later versions, can redirect to diff. behaviour (and DTO objects) for diff. versions.
            }

            cryptoScheme = manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>();
            switch (manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>()) {
                case ManifestCryptographyScheme.SymmetricOnly:
                    cryptoConfig =
                        manifestHeader.CryptographySchemeConfiguration
                                      .DeserialiseDto<SymmetricManifestCryptographyConfiguration>();
                    break;
                case ManifestCryptographyScheme.Um1Hybrid:
                    cryptoConfig =
                        manifestHeader.CryptographySchemeConfiguration
                                      .DeserialiseDto<Um1HybridManifestCryptographyConfiguration>();
                    break;
                default:
                    throw new NotSupportedException(String.Format(
                        "Package manifest cryptography scheme \"{0}\" as specified by the manifest header is unsupported/unknown.",
                        manifestHeader.CryptographySchemeName));
            }

            return manifestHeader;
        }

        /// <summary>
        ///     Reads the manifest from the package.
        /// </summary>
        /// <remarks>
        ///     Call method, supplying (all of) only the keys associated with the sender and the context.
        ///     This maximises the chance that: <br/>
        ///     <list type="number">
        ///         <item><description>
        ///             The package will be successfully decrypted if multiple 
        ///             keys are in use by both parties.
        ///         </description></item>
        ///         <item><description>
        ///             Minimises the time spent validating potential key pairs.
        ///         </description></item>
        ///     </list>
        /// </remarks>
        /// <param name="keyProvider">Provider to get possible keys for the manifest from.</param>
        /// <param name="manifestScheme">Cryptography scheme used in the manifest.</param>
        /// <returns>Package manifest object.</returns>
        /// <exception cref="ArgumentException">Key provider absent or could not supply any keys.</exception>
        /// <exception cref="NotSupportedException">Manifest cryptography scheme unsupported/unknown or missing.</exception>
        /// <exception cref="CryptoException">
        ///     A cryptographic operation failed (additional data maybe available in <see cref="CryptoException.InnerException"/>).
        /// </exception>
        /// <exception cref="KeyConfirmationException">
        ///     Key confirmation failed to determine a key, or failed unexpectedly 
        ///     (additional data maybe available in <see cref="KeyConfirmationException.InnerException"/>)
        /// </exception>
        /// <exception cref="InvalidDataException">
        ///     Deserialisation of manifest failed unexpectedly (manifest malformed, or incorrect key).
        /// </exception>
        /// <exception cref="CiphertextAuthenticationException">Manifest not authenticated.</exception>
        private Manifest ReadManifest(IKeyProvider keyProvider, ManifestCryptographyScheme manifestScheme)
        {
            // Determine the pre-key for the package manifest decryption (different schemes use different approaches)
            byte[] preMKey = null;
            switch (manifestScheme) {
                case ManifestCryptographyScheme.SymmetricOnly:
                {
                    if (keyProvider.SymmetricKeys.Any() == false) {
                        throw new ArgumentException("No symmetric keys available for decryption of this manifest.",
                            "keyProvider");
                    }
                    SymmetricKey symmetricKey = null;
                    if (_manifestCryptoConfig.KeyConfirmation != null) {
                        try {
                            symmetricKey = ConfirmationUtility.ConfirmKeyFromCanary(
                                ((SymmetricManifestCryptographyConfiguration)_manifestCryptoConfig).KeyConfirmation,
                                _manifestCryptoConfig.KeyConfirmationVerifiedOutput, keyProvider.SymmetricKeys);
                        } catch (Exception e) {
                            throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                        }
                    } else {
                        if (keyProvider.SymmetricKeys.Count() > 1) {
                            // Possibly allow to proceed anyway and just look for a serialisation failure? (not implemented)
                            throw new ArgumentException(
                                "Multiple symmetric keys are available, but confirmation is unavailable.",
                                "keyProvider",
                                new ConfigurationInvalidException("Package manifest includes no key confirmation data."));
                        }
                        preMKey = keyProvider.SymmetricKeys.First().Key;
                    }
                    if (symmetricKey != null) {
                        preMKey = symmetricKey.Key;
                    }
                    break;
                } 
                case ManifestCryptographyScheme.Um1Hybrid:
                {
                    EcKey um1SenderKey;
                    EcKeypair um1RecipientKeypair;
                    EcKey um1EphemeralKey =
                        ((Um1HybridManifestCryptographyConfiguration) _manifestCryptoConfig).EphemeralKey;
                    if (_manifestCryptoConfig.KeyConfirmation != null) {
                        try {
                            ConfirmationUtility.ConfirmKeyFromCanary(_manifestCryptoConfig.KeyConfirmation,
                                _manifestCryptoConfig.KeyConfirmationVerifiedOutput,
                                keyProvider.ForeignEcKeys,
                                um1EphemeralKey,
                                keyProvider.EcKeypairs,
                                out um1SenderKey, out um1RecipientKeypair);
                        } catch (Exception e) {
                            throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                        }
                    } else {
                        // No key confirmation capability available
                        if (keyProvider.ForeignEcKeys.Count() > 1 || keyProvider.EcKeypairs.Count() > 1) {
                            throw new KeyConfirmationException(
                                "Multiple EC keys have been provided where the package provides no key confirmation capability.");
                        }
                        um1SenderKey = keyProvider.ForeignEcKeys.First();
                        um1RecipientKeypair = keyProvider.EcKeypairs.First();
                    }
                    // Perform the UM1 key agreement
                    try {
                        preMKey = Um1Exchange.Respond(um1SenderKey, um1RecipientKeypair.GetPrivateKey(),
                                um1EphemeralKey);
                    } catch (Exception e) {
                        throw new CryptoException("Unexpected error in UM1 key agreement.", e);
                    }
                    break;
                }
                default:
                    throw new NotSupportedException(
                        String.Format("Manifest cryptography scheme \"{0}\" is unsupported/unknown.", manifestScheme));
            }

            if (preMKey.IsNullOrZeroLength()) {
                throw new KeyConfirmationException(String.Format(
                    "None of the keys provided to decrypt the manifest (cryptographic scheme: {0}) were confirmed as being able to do so.",
                    manifestScheme));
            }
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest pre-key",
                preMKey.ToHexString()));

            // Derive working manifest encryption & authentication keys from the manifest pre-key
            byte[] workingManifestCipherKey, workingManifestMacKey;
            try {
                int cipherKeySizeBytes = _manifestCryptoConfig.SymmetricCipher.KeySizeBits.BitsToBytes();
                if (_manifestCryptoConfig.Authentication.KeySizeBits.HasValue == false) {
                    throw new ConfigurationInvalidException("Manifest authentication key size is missing.");
                }
                int macKeySizeBytes = _manifestCryptoConfig.Authentication.KeySizeBits.Value.BitsToBytes();
                // Derive working cipher and MAC keys from the pre-key
                KeyStretchingUtility.DeriveWorkingKeys(
                    preMKey, 
                    cipherKeySizeBytes, macKeySizeBytes, 
                    _manifestCryptoConfig.KeyDerivation,
                    out workingManifestCipherKey, out workingManifestMacKey);
            } catch (Exception e) {
                throw new CryptoException("Unexpected error in manifest key derivation.", e);
                // TODO: make a specialised exception to communicate the failure type
            }

            // Clear the manifest pre-key
            preMKey.SecureWipe();

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest working key",
                workingManifestCipherKey.ToHexString()));
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest",
                "Manifest length prefix offset (absolute)",
                _readingStream.Position));

            // Read manifest length prefix
            var manifestLengthLe = new byte[sizeof (UInt32)]; // in little-endian form
            int manifestLengthBytesRead = _readingStream.Read(manifestLengthLe, 0, sizeof (UInt32));
            if (manifestLengthBytesRead != sizeof (UInt32)) {
                throw new DataLengthException("Manifest length prefix could not be read. Insufficient data.");
            }
            manifestLengthLe.XorInPlaceInternal(0, workingManifestMacKey, 0, sizeof (UInt32)); // deobfuscate length
            UInt32 mlUInt = manifestLengthLe.LittleEndianToUInt32();
            var manifestLength = (int) mlUInt;

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest length",
                manifestLength));
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest offset (absolute)",
                _readingStream.Position));

            /* Read manifest */
            Manifest manifest;
            using (var decryptedManifestStream = new MemoryStream(manifestLength)) {
                byte[] manifestMac;
                try {
                    using (
                        var authenticator = new MacStream(_readingStream, false, _manifestCryptoConfig.Authentication,
                            out manifestMac, workingManifestMacKey, false)) {
                        using (var cs = new CipherStream(authenticator, false, _manifestCryptoConfig.SymmetricCipher,
                            workingManifestCipherKey, false)) {
                            cs.ReadExactlyTo(decryptedManifestStream, manifestLength, true);
                        }
                        // Authenticate manifest length tag
                        authenticator.Update(manifestLengthLe, 0, manifestLengthLe.Length);

                        byte[] manifestCryptoDtoForAuth;
                        switch (manifestScheme) {
                            case ManifestCryptographyScheme.SymmetricOnly:
                                manifestCryptoDtoForAuth =
                                    ((SymmetricManifestCryptographyConfiguration) _manifestCryptoConfig)
                                        .CreateAuthenticatibleClone().SerialiseDto();
                                break;
                            case ManifestCryptographyScheme.Um1Hybrid:
                                manifestCryptoDtoForAuth =
                                    ((Um1HybridManifestCryptographyConfiguration) _manifestCryptoConfig)
                                        .CreateAuthenticatibleClone().SerialiseDto();
                                break;
                            default:
                                throw new NotSupportedException();
                        }
                        // Authenticate manifest cryptography configuration (from manifest header)
                        authenticator.Update(manifestCryptoDtoForAuth, 0, manifestCryptoDtoForAuth.Length);
                    }
                } catch (Exception e) {
                    throw new CryptoException("Unexpected error in manifest decrypt-then-MAC operation.", e);
                }

                // Verify that manifest authenticated successfully
                if (manifestMac.SequenceEqualConstantTime(_manifestCryptoConfig.AuthenticationVerifiedOutput) == false) {
                    throw new CiphertextAuthenticationException("Manifest failed authentication.");
                }
                decryptedManifestStream.Seek(0, SeekOrigin.Begin);

                Stream serialisedManifestStream;
                if (_manifestHeader.UseCompression) {
                    // Expose serialised manifest through decompressing decorator
                    serialisedManifestStream = new LZ4Stream(decryptedManifestStream, CompressionMode.Decompress);
                } else {
                    serialisedManifestStream = decryptedManifestStream;
                }

                try {
                    manifest = serialisedManifestStream.DeserialiseDto<Manifest>(false);
                } catch (Exception e) {
                    throw new InvalidDataException("Manifest failed to deserialise.", e);
                }
            }

            _readingPayloadStreamOffset = _readingStream.Position;

            // Clear the manifest encryption & authentication keys
            workingManifestCipherKey.SecureWipe();
            workingManifestMacKey.SecureWipe();

            return manifest;
        }

        /// <summary>
        ///     Unpacks/extracts the payload items into a directory.
        /// </summary>
        /// <param name="path">Path to write items to.</param>
        /// <param name="overwrite"></param>
        /// <param name="payloadKeys">Potential symmetric keys for payload items.</param>
        /// <exception cref="ConfigurationInvalidException">Package item path includes a relative-up specifier (security risk).</exception>
        /// <exception cref="NotSupportedException">Package includes a KeyAction payload item type (not implemented).</exception>
        /// <exception cref="IOException">File already exists and overwrite is not allowed.</exception>
        public void ReadToDirectory(string path, bool overwrite, IEnumerable<SymmetricKey> payloadKeys = null)
        {
            if (path == null) {
                throw new ArgumentNullException("path");
            }
            try {
                Directory.CreateDirectory(path);
            } catch (IOException) {
                throw new ArgumentException(
                    "Could not create package output directory: Supplied path is a file, not a directory.",
                    "path");
            } catch (ArgumentException) {
                throw new ArgumentException(
                    "Could not create package output directory: Path contains invalid characters.",
                    "path");
            } catch (NotSupportedException e) {
                throw new ArgumentException(
                    "Could not create package output directory: Path contains invalid character.",
                    "path", e);
            }

            foreach (PayloadItem item in _manifest.PayloadItems) {
                if (item.Type != PayloadItemType.KeyAction &&
                    item.Path.Contains(Athena.Packaging.PathRelativeUp)) {
                    throw new ConfigurationInvalidException("A payload item specifies a relative path outside that of the package root. "
                                                            + " This is a potentially dangerous condition.");
                }

                // First we correct the directory symbol to match local OS
                string relativePath = item.Path.Replace(Athena.Packaging.PathDirectorySeperator,
                    Path.DirectorySeparatorChar);
                string absolutePath = Path.Combine(path, relativePath);
                switch (item.Type) {
                    case PayloadItemType.Message:
                        if (Path.HasExtension(absolutePath) == false) {
                            absolutePath += ".txt";
                        }
                        break;
                    case PayloadItemType.KeyAction:
                        throw new NotSupportedException("Key actions not implemented.");
                }
                if (File.Exists(absolutePath) && overwrite == false) {
                    throw new IOException("File already exists: " + absolutePath);
                }

                PayloadItem itemClosureVar = item;
                item.SetStreamBinding(() => {
                    try {
                        var directory = Path.GetDirectoryName(absolutePath);
                        Directory.CreateDirectory(directory);
                        const int fileBufferSize = 81920; // 80 KB (Microsoft default)
                        var stream = new FileStream(absolutePath, FileMode.Create, FileAccess.Write,
                            FileShare.None, fileBufferSize, useAsync: true);
                        stream.SetLength(itemClosureVar.ExternalLength);
                        return stream;
                    } catch (ArgumentException e) {
                        throw new ConfigurationInvalidException(
                            "Could not create payload item output stream: path contains invalid characters.", e);
                    } catch (NotSupportedException e) {
                        throw new ConfigurationInvalidException(
                            "Could not create payload item output stream: path is invalid.", e);
                    }
                });
            }
            ReadPayload(payloadKeys);
        }

        /// <summary>
        ///     Read the payload.
        /// </summary>
        /// <remarks>
        ///     All payload items to be read must have have valid stream bindings 
        ///     (<see cref="PayloadItem.StreamBinding"/>) prior to calling this.
        /// </remarks>
        /// <param name="payloadKeys">Potential keys for payload items (optional).</param>
        /// <exception cref="KeyConfirmationException">Key confirmation for payload items failed.</exception>
        /// <exception cref="ConfigurationInvalidException">Payload layout scheme malformed/missing.</exception>
        /// <exception cref="InvalidDataException">Package data structure malformed.</exception>
        private void ReadPayload(IEnumerable<SymmetricKey> payloadKeys = null)
        {
            if (_readingPayloadStreamOffset != 0 && _readingStream.Position != _readingPayloadStreamOffset) {
                _readingStream.Seek(_readingPayloadStreamOffset, SeekOrigin.Begin);
            }

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "Read", "Payload offset (absolute)",
                _readingStream.Position));

            // Check that all payload items have decryption keys - if they do not, confirm them from potentials
            try {
                ConfirmItemPreKeys(payloadKeys);
            } catch (Exception e) {
                throw new KeyConfirmationException("Error in key confirmation of payload items.", e);
            }

            // Read the payload
            PayloadMux mux;
            try {
                var payloadScheme = _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>();
                mux = PayloadMultiplexerFactory.CreatePayloadMultiplexer(payloadScheme, false, _readingStream,
                    _manifest.PayloadItems,
                    _itemPreKeys, _manifest.PayloadConfiguration);
            } catch (EnumerationParsingException e) {
                throw new ConfigurationInvalidException(
                    "Payload layout scheme specified is unsupported/unknown or missing.", e);
            } catch (Exception e) {
                throw new Exception("Error in creation of payload demultiplexer.", e);
            }

            // Demux the payload
            try {
                mux.Execute();
            } catch (Exception e) {
                // Catch different kinds of exception in future
                throw new Exception("Error in demultiplexing payload.", e);
            }

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPayload", "Trailer offset (absolute)",
                _readingStream.Position));

            // Read the trailer
            byte[] referenceTrailerTag = Athena.Packaging.GetPackageTrailerTag();
            var trailerTag = new byte[referenceTrailerTag.Length];
            int trailerBytesRead = _readingStream.Read(trailerTag, 0, trailerTag.Length);
            if (trailerTag.SequenceEqualShortCircuiting(referenceTrailerTag) == false) {
                const string pragmatist =
                    "It would appear, however, that the package has unpacked successfully despite this.";
                if (trailerBytesRead != referenceTrailerTag.Length) {
                    throw new DataLengthException("Insufficient data to read package trailer tag. " + pragmatist);
                }
                throw new InvalidDataException("Package is malformed. Trailer tag is either absent or malformed."
                                               + pragmatist);
            }

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPayload",
                "[* PACKAGE END *] Offset (absolute)", _readingStream.Position));
        }

        public void Dispose()
        {
            if (_closeOnDispose && _readingStream != null) {
                _readingStream.Close();
            }
        }
    }
}
