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
using System.IO;
using System.Collections.Generic;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.DTO;
using ObscurCore.Packaging;
using System.Diagnostics;
using System.Linq;

using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyConfirmation;
using ObscurCore.Cryptography.KeyDerivation;

namespace ObscurCore
{
    /// <summary>
    /// Provides capability of reading ObscurCore packages.
    /// </summary>
    public class PackageReader
    {
        #region Instance variables

        /// <summary>
        /// Stream that package is being read from.
        /// </summary>
        private readonly Stream _readingStream;

        private readonly Manifest _manifest;
        private readonly ManifestHeader _manifestHeader;

        /// <summary>
        /// Configuration of the manifest cipher. Must be serialised into ManifestHeader when writing package.
        /// </summary>
        private readonly IManifestCryptographySchemeConfiguration _manifestCryptoConfig;

        private readonly Dictionary<Guid, byte[]> _itemPreKeys = new Dictionary<Guid, byte[]>();

        /// <summary>
        /// Offset at which the payload starts.
        /// </summary>
        private long _readingPayloadStreamOffset;

        #endregion

        #region Properties

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
        /// Configuration of symmetric cipher used for encryption of the manifest.
        /// </summary>
        public ICipherConfiguration ManifestCipher
        {
            get { return _manifestCryptoConfig.SymmetricCipher; }
        }

        /// <summary>
        /// Configuration of function used in verifying the authenticity/integrity of the manifest.
        /// </summary>
        public IVerificationFunctionConfiguration ManifestAuthentication
        {
            get { return _manifestCryptoConfig.Authentication; }
        }

        /// <summary>
        /// Configuration of key derivation used to derive encryption and authentication keys from prior key material. 
        /// These keys are used in those functions of manifest encryption/authentication, respectively.
        /// </summary>
        public IKeyDerivationConfiguration ManifestKeyDerivation
        {
            get { return _manifestCryptoConfig.KeyDerivation; }
        }

        /// <summary>
        /// Configuration of key confirmation used for confirming the cryptographic key 
        /// to be used as the basis for key derivation.
        /// </summary>
        public IVerificationFunctionConfiguration ManifestKeyConfirmation
        {
            get { return _manifestCryptoConfig.KeyConfirmation; }
        }

        /// <summary>
        /// Layout scheme configuration of the items in the payload.
        /// </summary>
        public PayloadLayoutScheme PayloadLayout
        {
            get
            {
                return _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>();
            }
        }

        public IEnumerable<IPayloadItem> PayloadItems
        {
            get
            {
                return _manifest.PayloadItems.Select(item => item as IPayloadItem);
            }
        }

        #endregion

        #region Constructors (including static methods that return a PackageReader)

        /// <summary>
        /// Constructor for static-origin inits (reads). 
        /// Immediately reads package manifest header and manifest.
        /// </summary>
        internal PackageReader(Stream stream, IKeyProvider keyProvider)
        {
            _readingStream = stream;
            ManifestCryptographyScheme mCryptoScheme;

            _manifestHeader = ReadManifestHeader(_readingStream, out mCryptoScheme, out _manifestCryptoConfig);
            _manifest = ReadManifest(keyProvider, mCryptoScheme);
        }

        /// <summary>
        /// Read a package from a file.
        /// </summary>
        /// <returns>Package ready for reading.</returns>
        /// <exception cref="ArgumentException">File does not exist at the path specified.</exception>
        public static PackageReader FromFile(string filePath, IKeyProvider keyProvider)
        {
            var file = new FileInfo(filePath);
            if (file.Exists == false) throw new ArgumentException();
            return FromStream(file.OpenRead(), keyProvider);
        }

        /// <summary>
        /// Read a package from a stream.
        /// </summary>
        /// <returns>Package ready for reading.</returns>
        public static PackageReader FromStream(Stream stream, IKeyProvider keyProvider)
        {
            return new PackageReader(stream, keyProvider);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Performs key confirmation and derivation on each payload item.
        /// </summary>
        /// <param name="payloadKeysSymmetric">Potential symmetric keys for payload items.</param>
        /// <exception cref="AggregateException">
        /// Consisting of ItemKeyMissingException, indicating items missing cryptographic keys.
        /// </exception>
        private void ConfirmItemPreKeys(IEnumerable<byte[]> payloadKeysSymmetric = null)
        {
            var keys = payloadKeysSymmetric != null ? payloadKeysSymmetric.ToList() : new List<byte[]>();
            var errorList = new List<PayloadItem>();
            foreach (var item in _manifest.PayloadItems.Where(item => item.CipherKey.IsNullOrZeroLength() ||
                item.AuthenticationKey.IsNullOrZeroLength())) {
                if (item.KeyConfirmation == null || item.KeyDerivation == null) {
                    errorList.Add(item);
                }
                // We will derive the key from one supplied as a potential
                var preIKey = ConfirmationUtility.ConfirmSymmetricKey(item.KeyConfirmation, item.KeyConfirmationVerifiedOutput, keys);
                if (preIKey.IsNullOrZeroLength()) {
                    errorList.Add(item);
                }
                if (errorList.Count == 0 && _itemPreKeys.ContainsKey(item.Identifier) == false) {
                    _itemPreKeys.Add(item.Identifier, preIKey);
                }
            }
            if (errorList.Count > 0) {
                throw new AggregateException(errorList.Select(item => new ItemKeyMissingException(item)));
            }
        }

        #endregion

        /// <summary>
        /// Reads a package manifest header (only) from a stream.
        /// </summary>
        /// <param name="sourceStream">Stream to read the header from.</param>
        /// <param name="cryptoScheme">Manifest cryptography scheme parsed from the header.</param>
        /// <param name="cryptoConfig">Manifest cryptography configuration deserialised from the header.</param>
        /// <returns>Package manifest header object.</returns>
        /// <exception cref="DataLengthException">End of stream encountered unexpectedly (contents truncated).</exception>
        /// <exception cref="InvalidDataException">Package data structure is out of specification or otherwise malformed.</exception>
        /// <exception cref="NotSupportedException">Version format specified is unknown to the local version.</exception>
        private static ManifestHeader ReadManifestHeader(Stream sourceStream, out ManifestCryptographyScheme cryptoScheme, 
            out IManifestCryptographySchemeConfiguration cryptoConfig)
        {
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifestHeader", "[* PACKAGE START* ] Header offset (absolute)",
                sourceStream.Position));

            var referenceHeaderTag = Athena.Packaging.GetHeaderTag();
            var readHeaderTag = new byte[referenceHeaderTag.Length];
            var headerTagBytesRead = sourceStream.Read(readHeaderTag, 0, readHeaderTag.Length);
            if (readHeaderTag.SequenceEqual(referenceHeaderTag) == false) {
                if (headerTagBytesRead != referenceHeaderTag.Length) {
                    throw new DataLengthException("Insufficient data to read package header tag.");
                }
                throw new InvalidDataException("Package is malformed. Expected header tag is either absent or malformed.");
            }

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifestHeader", "Manifest header offset (absolute)",
                sourceStream.Position));

            var manifestHeader = StratCom.DeserialiseDataTransferObject<ManifestHeader>(sourceStream);

            if (manifestHeader.FormatVersion <= 0) {
                throw new InvalidDataException("Package format descriptor is 0 or less (must be 1 or more).");
            } else if (manifestHeader.FormatVersion > Athena.Packaging.HeaderVersion) {
                throw new NotSupportedException(String.Format("Package version {0} as specified by the manifest header is unsupported/unknown.\n" +
                    "The local version of ObscurCore supports up to version {1}.", manifestHeader.FormatVersion, Athena.Packaging.HeaderVersion));
                // In later versions, can redirect to diff. behaviour (and DTO objects) for diff. versions.
            }

            cryptoScheme = manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>();
            switch (manifestHeader.CryptographySchemeName.ToEnum<ManifestCryptographyScheme>()) {
                case ManifestCryptographyScheme.SymmetricOnly:
                    cryptoConfig = StratCom.DeserialiseDataTransferObject<SymmetricManifestCryptographyConfiguration>
                                   (manifestHeader.CryptographySchemeConfiguration);
                    break;
                case ManifestCryptographyScheme.Um1Hybrid:
                    cryptoConfig = StratCom.DeserialiseDataTransferObject<Um1HybridManifestCryptographyConfiguration>
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
        /// <exception cref="ArgumentException">Key provider absent or could not supply any keys.</exception>
        /// <exception cref="NotSupportedException">Manifest cryptography scheme unsupported/unknown or missing.</exception>
        /// <exception cref="KeyConfirmationException">
        /// Key confirmation failed to determine a key, or failed unexpectedly. InnerException may have details.
        /// </exception>
        /// <exception cref="InvalidDataException">
        /// Deserialisation of manifest failed unexpectedly (manifest malformed, or incorrect key).
        /// </exception>
        /// <exception cref="CiphertextAuthenticationException">Manifest not authenticated.</exception>
        private Manifest ReadManifest(IKeyProvider keyProvider, ManifestCryptographyScheme manifestScheme)
        {
            // Determine the pre-key for the package manifest decryption (different schemes use different approaches)
            byte[] preMKey;
            switch (manifestScheme) {
                case ManifestCryptographyScheme.SymmetricOnly:
                    if (keyProvider.SymmetricKeys.Any() == false) {
                        throw new ArgumentException("No symmetric keys available for decryption of this manifest.",
                            "keyProvider");
                    }
                    if (_manifestCryptoConfig.KeyConfirmation != null) {
                        try {
                            preMKey = ConfirmationUtility.ConfirmSymmetricKey(
                                ((SymmetricManifestCryptographyConfiguration)_manifestCryptoConfig).KeyConfirmation,
                                _manifestCryptoConfig.KeyConfirmationVerifiedOutput, keyProvider.SymmetricKeys);
                        } catch (Exception e) {
                            throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                        }
                    } else {
                        if (keyProvider.SymmetricKeys.Count() > 1) {
                            // Possibly allow to proceed anyway and just look for a serialisation failure? (not implemented)
                            throw new ArgumentException("Multiple symmetric keys are available, but confirmation is unavailable.",
                                "keyProvider", new ConfigurationInvalidException("Package manifest includes no key confirmation data."));
                        }
                        preMKey = keyProvider.SymmetricKeys.First();
                    }
                    break;
                case ManifestCryptographyScheme.Um1Hybrid:
                    // Identify matching public-private key pairs based on curve provider and curve name
                    var um1EphemeralKey = ((Um1HybridManifestCryptographyConfiguration)_manifestCryptoConfig).EphemeralKey;

                    if (_manifestCryptoConfig.KeyConfirmation != null) {
                        try {
                            // Project the keypairs to only private keys
                            var um1ReceiverKeys = keyProvider.EcKeypairs.Select(keypair => keypair.GetPrivateKey());
                            preMKey = ConfirmationUtility.ConfirmUM1HybridKey(_manifestCryptoConfig.KeyConfirmation,
                                _manifestCryptoConfig.KeyConfirmationVerifiedOutput,
                                um1EphemeralKey, keyProvider.ForeignEcKeys, um1ReceiverKeys);
                        } catch (Exception e) {
                            throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                        }
                    } else {
                        // No key confirmation capability available
                        if (keyProvider.ForeignEcKeys.Count() > 1 || keyProvider.EcKeypairs.Count() > 1) {
                            throw new KeyConfirmationException("Multiple EC keys have been provided where the package provides no key confirmation capability.");
                        }

                        var localKey = keyProvider.EcKeypairs.First().GetPrivateKey();
                        var foreignKey = keyProvider.ForeignEcKeys.First();
                        try {
                            preMKey = Um1Exchange.Respond(foreignKey, localKey, um1EphemeralKey);
                        } catch (Exception e) {
                            throw new CryptoException("Unexpected error in UM1 key agreement.", e);
                        }
                    }
                    break;
                default:
                    throw new NotSupportedException(String.Format("Manifest cryptography scheme \"{0}\" is unsupported/unknown.", manifestScheme));
            }

            if (preMKey == null || preMKey.Length == 0) {
                throw new KeyConfirmationException(String.Format(
                    "None of the keys provided to decrypt the manifest (cryptographic scheme: {0}) were confirmed as being able to do so.", manifestScheme));
            }
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest pre-key",
                preMKey.ToHexString()));

            // Derive working manifest encryption & authentication keys from the manifest pre-key
            byte[] workingManifestCipherKey, workingManifestMacKey;
            try {
                KeyStretchingUtility.DeriveWorkingKeys(preMKey, _manifestCryptoConfig.SymmetricCipher.KeySizeBits / 8,
                    _manifestCryptoConfig.Authentication.KeySizeBits.Value / 8, _manifestCryptoConfig.KeyDerivation,
                    out workingManifestCipherKey, out workingManifestMacKey);
            } catch (Exception e) {
                throw new CryptoException("Unexpected error in manifest key derivation.", e); // make a specialised exception to communicate the failure type
            }

            // Clear the manifest pre-key
            preMKey.SecureWipe();

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest working key",
                workingManifestCipherKey.ToHexString()));
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest length prefix offset (absolute)",
                _readingStream.Position));

            // Read manifest length prefix
            Manifest manifest;

            var manifestLengthLe = new byte[sizeof(UInt32)]; // in little-endian form
            var manifestLengthBytesRead = _readingStream.Read(manifestLengthLe, 0, sizeof(UInt32));
            if (manifestLengthBytesRead != sizeof (UInt32)) {
                throw new DataLengthException("Manifest length prefix could not be read. Insufficient data.");
            }
            manifestLengthLe.XorInPlaceInternal(0, workingManifestMacKey, 0, sizeof(UInt32)); // deobfuscate length
            UInt32 mlUInt = manifestLengthLe.LittleEndianToUInt32();
            int manifestLength = (int)mlUInt;

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest length",
                manifestLength));
            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest offset (absolute)",
                _readingStream.Position));

            /* Read manifest */
            using (var decryptedManifestStream = new MemoryStream((int)(manifestLength * 0.1))) {
                byte[] manifestMac = null;
                try {
                    using (var authenticator = new MacStream(_readingStream, false, _manifestCryptoConfig.Authentication,
                        out manifestMac, workingManifestMacKey, closeOnDispose: false)) {
                        using (var cs = new CipherStream(authenticator, false, _manifestCryptoConfig.SymmetricCipher,
                            workingManifestCipherKey, closeOnDispose: false)) {
                            cs.ReadExactlyTo(decryptedManifestStream, manifestLength, true);
                        }
                        authenticator.Update(manifestLengthLe, 0, manifestLengthLe.Length);

                        byte[] manifestCryptoDtoForAuth;
                        switch (manifestScheme) {
                            case ManifestCryptographyScheme.SymmetricOnly:
                                manifestCryptoDtoForAuth =
                                    ((SymmetricManifestCryptographyConfiguration)_manifestCryptoConfig).CreateAuthenticatibleClone().SerialiseDto();
                                break;
                            case ManifestCryptographyScheme.Um1Hybrid:
                                manifestCryptoDtoForAuth =
                                    ((Um1HybridManifestCryptographyConfiguration)_manifestCryptoConfig).CreateAuthenticatibleClone().SerialiseDto();
                                break;
                            default:
                                throw new NotSupportedException();
                        }
                        authenticator.Update(manifestCryptoDtoForAuth, 0, manifestCryptoDtoForAuth.Length);
                    }
                } catch (Exception e) {
                    throw new CryptoException("Unexpected error in manifest decrypt-then-MAC operation.", e);
                }

                // Authenticate the manifest
                if (manifestMac.SequenceEqualConstantTime(_manifestCryptoConfig.AuthenticationVerifiedOutput) == false) {
                    throw new CiphertextAuthenticationException("Manifest not authenticated.");
                }
                decryptedManifestStream.Seek(0, SeekOrigin.Begin);
                try {
                    manifest = (Manifest)StratCom.Serialiser.Deserialize(decryptedManifestStream, null, typeof(Manifest));
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
        /// Read a package into a directory. Just like extracting an archive.
        /// </summary>
        /// <param name="path">Path to write items to.</param>
        /// <param name="overwrite"></param>
        /// <param name="payloadKeys">Potential symmetric keys for payload items.</param>
        /// <exception cref="ConfigurationInvalidException">Package item path includes a relative-up specifier (security risk).</exception>
        /// <exception cref="NotSupportedException">Package includes a KeyAction payload item type (not implemented).</exception>
        /// <exception cref="IOException">File already exists and overwrite is not allowed.</exception>
        public void ReadToDirectory(string path, bool overwrite, IEnumerable<byte[]> payloadKeys = null)
        {
            var directory = new DirectoryInfo(path);
            if (directory.Exists == false) {
                directory.Create();
            }

            foreach (var item in _manifest.PayloadItems) {
                if (item.Type != PayloadItemType.KeyAction && item.RelativePath.Contains(Athena.Packaging.PathRelativeUp)) {
                    throw new ConfigurationInvalidException("A payload item specifies a relative path outside that of the package root. "
                    + " This is a potentially dangerous condition.");
                }

                // First we correct the directory symbol to match local OS
                var relativePath = item.RelativePath.Replace(Athena.Packaging.PathDirectorySeperator, Path.DirectorySeparatorChar);
                var absolutePath = Path.Combine(path, relativePath);
                switch (item.Type) {
                    case PayloadItemType.Utf8:
                    case PayloadItemType.Utf32:
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

                item.SetStreamBinding(() => new FileStream(absolutePath, FileMode.Create));
            }
            ReadPayload(payloadKeys);
        }

        /// <summary>
        /// Read payload from package.
        /// </summary>
        /// <param name="payloadKeys">Potential keys for payload items (optional).</param>
        /// <exception cref="ConfigurationInvalidException">Payload layout scheme malformed/missing.</exception>
        /// <exception cref="InvalidDataException">Package data structure malformed.</exception>
        private void ReadPayload(IEnumerable<byte[]> payloadKeys = null)
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
                mux = PayloadMultiplexerFactory.CreatePayloadMultiplexer(payloadScheme, false, _readingStream, _manifest.PayloadItems,
                    _itemPreKeys, _manifest.PayloadConfiguration);
            } catch (EnumerationParsingException e) {
                throw new ConfigurationInvalidException("Payload layout scheme specified is unsupported/unknown or missing.", e);
            } catch (Exception e) {
                throw new Exception("Error in creation of payload demultiplexer.", e);
            }

            // Demux the payload
            try {
                mux.Execute();
            } catch (Exception e) {
                // Catch different kinds of exception in future
                throw new Exception("Error in demultiplexing payload items.", e);
            }

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPayload", "Trailer offset (absolute)",
                _readingStream.Position));

            // Read the trailer
            var referenceTrailerTag = Athena.Packaging.GetTrailerTag();
            var trailerTag = new byte[referenceTrailerTag.Length];
            var trailerBytesRead = _readingStream.Read(trailerTag, 0, trailerTag.Length);
            if (trailerTag.SequenceEqual(referenceTrailerTag) == false) {
                const string pragmatist =
                    "It would appear, however, that the package has unpacked successfully despite this.";
                if (trailerBytesRead != referenceTrailerTag.Length) {
                    throw new DataLengthException("Insufficient data to read package trailer tag. " + pragmatist);
                }
                throw new InvalidDataException("Package is malformed. Trailer tag is either absent or malformed."
                    + pragmatist);
            }

            Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPayload", "[* PACKAGE END *] Offset (absolute)",
                _readingStream.Position));
        }
    }
}
