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
		/// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
		internal CipherConfiguration ManifestCipher {
			get { return _manifestCryptoConfig.SymmetricCipher; }
		}

		/// <summary>
		/// Configuration of function used in verifying the authenticity/integrity of the manifest.
		/// </summary>
		/// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
		internal VerificationFunctionConfiguration ManifestAuthentication {
			get { return _manifestCryptoConfig.Authentication; }
		}

		/// <summary>
		/// Configuration of key derivation used to derive encryption and authentication keys from prior key material. 
		/// These keys are used in those functions of manifest encryption/authentication, respectively.
		/// </summary>
		/// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
		internal KeyDerivationConfiguration ManifestKeyDerivation {
			get { return _manifestCryptoConfig.KeyDerivation; }
		}

		/// <summary>
		/// Configuration of key confirmation used for confirming the cryptographic key 
		/// to be used as the basis for key derivation.
		/// </summary>
		/// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
		internal VerificationFunctionConfiguration ManifestKeyConfirmation {
			get { return _manifestCryptoConfig.KeyConfirmation; }
		}

		/// <summary>
		/// Layout scheme configuration of the items in the payload.
		/// </summary>
		/// <exception cref="InvalidOperationException">Package is being read, not written.</exception>
		public PayloadLayoutScheme PayloadLayout
		{
			get {
				return _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme>();
			}
		}


		/// <summary>
		/// Read a package from a file.
		/// </summary>
		/// <returns>Package ready for reading.</returns>
		/// <exception cref="ArgumentException">File does not exist at the path specified.</exception>
		public static PackageReader FromFile (string filePath, IKeyProvider keyProvider) {
			var file = new FileInfo(filePath);
			if (file.Exists == false) throw new ArgumentException();
			return FromStream(file.OpenRead(), keyProvider);
		}

		/// <summary>
		/// Read a package from a stream.
		/// </summary>
		/// <returns>Package ready for reading.</returns>
		public static PackageReader FromStream (Stream stream, IKeyProvider keyProvider) {
			return new PackageReader(stream, keyProvider);
		}

		/// <summary>
		/// Constructor for static-origin inits (reads). 
		/// Immediately reads package manifest header and manifest.
		/// </summary>
		internal PackageReader (Stream stream, IKeyProvider keyProvider) {
			_readingStream = stream;
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
		private static ManifestHeader ReadManifestHeader (Stream sourceStream, out IManifestCryptographySchemeConfiguration cryptoConfig,
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
		/// <exception cref="ArgumentException">Key provider absent or did not supply any keys.</exception>
		/// <exception cref="NotSupportedException">Manifest cryptography scheme unsupported/unknown or missing.</exception>
		/// <exception cref="KeyConfirmationException">Key confirmation failed to determine a key, or failed unexpectedly.</exception>
		/// <exception cref="InvalidDataException">Deserialisation of manifest failed unexpectedly.</exception>
		private Manifest ReadManifest (IKeyProvider keyProvider, ManifestCryptographyScheme manifestScheme) {
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
							_manifestCryptoConfig.KeyConfirmationVerifiedOutput, keyProvider.SymmetricKeys);
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
				var um1EphemeralKey = ((Um1HybridManifestCryptographyConfiguration) _manifestCryptoConfig).EphemeralKey;

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
					preMKey = UM1Exchange.Respond(keyProvider.ForeignEcKeys.First(),
						keyProvider.EcKeypairs.First().GetPrivateKey(), um1EphemeralKey);
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
			KeyStretchingUtility.DeriveWorkingKeys (preMKey, _manifestCryptoConfig.SymmetricCipher.KeySizeBits / 8,
				_manifestCryptoConfig.Authentication.KeySizeBits.Value / 8, _manifestCryptoConfig.KeyDerivation, 
				out workingManifestCipherKey, out workingManifestMacKey);

			// Clear the manifest pre-key
			Array.Clear(preMKey, 0, preMKey.Length);

			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest working key",
				workingManifestCipherKey.ToHexString()));
			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest length prefix offset (absolute)", 
				_readingStream.Position));

			// Read manifest length prefix
			Manifest manifest;

			byte[] manifestLengthLEBytes = new byte[sizeof(UInt32)];
			_readingStream.Read (manifestLengthLEBytes, 0, manifestLengthLEBytes.Length);
            manifestLengthLEBytes.XorInPlaceInternal(0, workingManifestMacKey, 0, sizeof(uint)); // deobfuscate length
			uint mlUInt = manifestLengthLEBytes.LittleEndianToUInt32 ();
			int manifestLength = (int)mlUInt;

			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest length prefix",
				manifestLength));
			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadManifest", "Manifest offset (absolute)",
				_readingStream.Position));

			/* Read manifest */
			using (var decryptedManifestStream = new MemoryStream ()) {
				byte[] manifestMac = null;
				using (var authenticator = new MacStream (_readingStream, false, _manifestCryptoConfig.Authentication, 
					out manifestMac, workingManifestMacKey, closeOnDispose : false)) 
				{
					using (var cs = new CipherStream (authenticator, false, _manifestCryptoConfig.SymmetricCipher, 
						workingManifestCipherKey, closeOnDispose : false)) 
					{
						cs.ReadExactlyTo (decryptedManifestStream, manifestLength, true);
					}

					authenticator.Update (manifestLengthLEBytes, 0, manifestLengthLEBytes.Length);

					byte[] manifestCryptoDtoForAuth;
					switch (manifestScheme) {
					case ManifestCryptographyScheme.SymmetricOnly:
						manifestCryptoDtoForAuth = 
							((SymmetricManifestCryptographyConfiguration)_manifestCryptoConfig).CreateAuthenticatibleClone().SerialiseDto ();
						break;
					case ManifestCryptographyScheme.UM1Hybrid:
						manifestCryptoDtoForAuth = 
							((Um1HybridManifestCryptographyConfiguration)_manifestCryptoConfig).CreateAuthenticatibleClone().SerialiseDto ();
						break;
					default:
						throw new InvalidOperationException ();
					}

					authenticator.Update (manifestCryptoDtoForAuth, 0, manifestCryptoDtoForAuth.Length);
				}

				// Authenticate the manifest
				if (manifestMac.SequenceEqualConstantTime (_manifestCryptoConfig.AuthenticationVerifiedOutput) == false) {
					throw new CiphertextAuthenticationException ("Manifest not authenticated.");
				}
				decryptedManifestStream.Seek (0, SeekOrigin.Begin);
				try {
					manifest = (Manifest)StratCom.Serialiser.Deserialize (decryptedManifestStream, null, typeof(Manifest));
				} catch (Exception e) {
					throw new InvalidDataException ("Manifest failed to deserialise.", e);
				}
			}

			_readingPayloadStreamOffset = _readingStream.Position;

			// Clear the manifest encryption & authentication keys
			workingManifestCipherKey.SecureWipe ();
			workingManifestMacKey.SecureWipe ();

			return manifest;
		}

		/// <summary>
		/// Performs key confirmation and derivation on each payload item.
		/// </summary>
		/// <param name="payloadKeysSymmetric">Potential symmetric keys for payload items.</param>
		/// <exception cref="AggregateException">
		/// Consisting of ItemKeyMissingException, indicating items missing cryptographic keys.
		/// </exception>
		private void ConfirmItemPreKeys (IEnumerable<byte[]> payloadKeysSymmetric = null) {
			var keys = payloadKeysSymmetric != null ? payloadKeysSymmetric.ToList() : new List<byte[]>();
			var errorList = new List<PayloadItem>();
			foreach (var item in _manifest.PayloadItems.Where(item => item.EncryptionKey.IsNullOrZeroLength() || 
				item.AuthenticationKey.IsNullOrZeroLength())) 
			{
				if(item.KeyConfirmation == null || item.KeyDerivation == null) {
					errorList.Add(item);
				}
				// We will derive the key from one supplied as a potential
				var preIKey = ConfirmationUtility.ConfirmSymmetricKey(item.KeyConfirmation, item.KeyConfirmationVerifiedOutput, keys);
				if (preIKey.IsNullOrZeroLength()) {
					errorList.Add(item);
				}
				if (errorList.Count == 0 && _itemPreKeys.ContainsKey(item.Identifier) == false) {
					_itemPreKeys.Add (item.Identifier, preIKey);
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
		/// <exception cref="NotImplementedException">Package includes a KeyAction payload item type (not implemented).</exception>
		public void ReadToDirectory(string path, IEnumerable<byte[]> payloadKeys = null) {
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
        /// <exception cref="ConfigurationValueInvalidException">Payload layout scheme malformed/missing.</exception>
		/// <exception cref="InvalidDataException">Package data structure malformed.</exception>
		private void ReadPayload (IEnumerable<byte[]> payloadKeys = null) {
            if (_readingPayloadStreamOffset != 0 && _readingStream.Position != _readingPayloadStreamOffset) {
                _readingStream.Seek(_readingPayloadStreamOffset, SeekOrigin.Begin);
            }

			Debug.Print(DebugUtility.CreateReportString("PackageReader", "Read", "Payload offset (absolute)",
				_readingStream.Position));

			// Check that all payload items have decryption keys - if they do not, confirm them from potentials
			ConfirmItemPreKeys(payloadKeys);

			// Read the payload
			PayloadLayoutScheme payloadScheme;
			try {
				payloadScheme = _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutScheme> ();
			} catch (Exception) {
                throw new ConfigurationInvalidException("Payload layout scheme specified is unsupported/unknown or missing.");
			}
			var mux = PayloadMultiplexerFactory.CreatePayloadMultiplexer (payloadScheme, false, _readingStream, _manifest.PayloadItems, 
				_itemPreKeys, _manifest.PayloadConfiguration);

			// Demux the payload
			try {
				mux.Execute ();
			} catch (Exception ex) {
				// Catch different kinds of exception in future
				throw;
			}

			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPayload", "Trailer offset (absolute)",
				_readingStream.Position));

			// Read the trailer
			var referenceHeaderTag = Athena.Packaging.GetTrailerTag();
			var readTrailerTag = new byte[referenceHeaderTag.Length];
			_readingStream.Read (readTrailerTag, 0, readTrailerTag.Length);
			if(!readTrailerTag.SequenceEqual(referenceHeaderTag)) {
				throw new InvalidDataException("Package is malformed. Trailer tag is either absent or malformed." 
					+ "It would appear, however, that the package has unpacked successfully despite this.");
			}

			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPayload", "[* PACKAGE END *] Offset (absolute)",
				_readingStream.Position));
		}
	}
}
