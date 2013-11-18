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
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyConfirmation;
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Extensions.ByteArrays;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.EllipticCurve;
using ObscurCore.Extensions.Streams;
using ProtoBuf;

// This code file contains all StratCom functionality relating to packaging/unpackaging.

namespace ObscurCore.Packaging
{
    public static class PackageWriter
    {
        /// <summary>
        /// Writes a package with symmetric manifest encryption. 
        /// The manifest key must be known to both parties.
        /// </summary>
        /// <param name="destination">Destination stream.</param>
        /// <param name="temp">Stream location to store payload data in temporarily. May be safely destroyed after completion.</param>
        /// <param name="manifest">Manifest object describing the package contents and configuration.</param>
        /// <param name="manifestCipherConfig">Symmetric encryption cipher configuration.</param>
        /// <param name="preMKey">Cryptographic key for the manifest encryption operation (after further derivation).</param>
        /// <param name="payloadKeys">Cryptographic keys for any items that do not have their Key field filled.</param>
        public static void WritePackageSymmetric(Stream destination, Stream temp, Manifest manifest,
                                                 SymmetricCipherConfiguration manifestCipherConfig, byte[] preMKey,
                                                 bool confirm = true, Dictionary<Guid, byte[]> payloadKeys = null)
        {
            // At the moment, we'll just force scrypt KDF and default parameters for it
            var mCrypto = new SymmetricManifestCryptographyConfiguration {
                    SymmetricCipher = manifestCipherConfig,
                    KeyDerivation = CreateDefaultManifestKeyDerivation(manifestCipherConfig.KeySize / 8)
                };
            if (confirm) mCrypto.KeyConfirmation = ConfirmationUtility.CreateDefaultManifestKeyConfirmation(preMKey);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackageSymmetric", "Manifest pre-key",
                preMKey.ToHexString()));

            // Derive the key which will be used for encrypting the package manifest
            var workingMKey = Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                preMKey, mCrypto.KeyDerivation.Salt, mCrypto.SymmetricCipher.KeySize,
                mCrypto.KeyDerivation.SchemeConfiguration);

            // Clear the pre-key from memory
            Array.Clear(preMKey, 0, preMKey.Length);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackageSymmetric", "Manifest working key",
                workingMKey.ToHexString()));

            var mCryptoBytes = mCrypto.SerialiseDTO();

            // Manifest cryptography configuration has been serialised into memory, 
            // so we can now populate the SymmetricCipherConfiguration inside it to streamline things...
            mCrypto.SymmetricCipher.Key = workingMKey;

            var mHeader = new ManifestHeader {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.UniversalSymmetric.ToString(),
                    CryptographySchemeConfiguration = mCryptoBytes
                };

            WritePackage(destination, temp, mHeader, manifest, mCrypto.SymmetricCipher);
        }

        /// <summary>
        /// Writes a package utillising Curve25519-based UM1 (one-pass elliptic curve) manifest cryptography.
        /// </summary>
        /// <param name="destination">Destination stream.</param>
        /// <param name="temp">Stream location to store payload data in temporarily. May be safely destroyed after completion.</param>
        /// <param name="manifest">Manifest object describing the package contents and configuration.</param>
        /// <param name="manifestCipherConfig">Symmetric encryption cipher configuration.</param>
        /// <param name="sender">Elliptic curve cryptographic key for the sender (local user).</param>
        /// <param name="recipient">Elliptic curve cryptographic key for the recipient (remote user).</param>
        /// <param name="payloadKeys">Cryptographic keys for any items that do not have their Key field filled.</param>
        public static void WritePackageCurve25519UM1Hybrid(Stream destination, Stream temp, Manifest manifest,
                                                     SymmetricCipherConfiguration manifestCipherConfig,
                                                     byte[] sender, byte[] recipient,
                                                     Dictionary<Guid, byte[]> payloadKeys = null) 
        {
            if (sender.Length != 32) {
                throw new ArgumentException(
                    "Sender's Curve25519 elliptic curve private key is not 32 bytes in length.", "sender");
            }
            if (recipient.Length != 32) {
                throw new ArgumentException(
                    "Recipient's Curve25519 elliptic curve public key is not 32 bytes in length.", "recipient");
            }

            // At the moment, we'll just force scrypt KDF and default parameters for it
            var mCrypto = new UM1ManifestCryptographyConfiguration {
                    SymmetricCipher = manifestCipherConfig,
                    KeyDerivation = CreateDefaultManifestKeyDerivation(manifestCipherConfig.KeySize / 8),
                };
            StratCom.EntropySource.NextBytes(mCrypto.KeyDerivation.Salt);

            byte[] ephemeralMKey;
            byte[] preMKey = Curve25519UM1Exchange.Initiate(recipient, sender, out ephemeralMKey);

            // Store the ephemeral public key in the manifest cryptography configuration object
            mCrypto.EphemeralKey.EncodedKey = ephemeralMKey;

            // Generate key confirmation for manifest
            mCrypto.KeyConfirmation = ConfirmationUtility.CreateDefaultManifestKeyConfirmation(preMKey);

            // Clear the public and private Curve25519 keys
            Array.Clear(sender, 0, sender.Length);
            Array.Clear(recipient, 0, recipient.Length);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackageCurve25519UM1", "Manifest pre-key",
                preMKey.ToHexString()));

            var workingMKey = Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                    preMKey, mCrypto.KeyDerivation.Salt,
                    mCrypto.SymmetricCipher.KeySize,
                    mCrypto.KeyDerivation.SchemeConfiguration);

            // Clear the pre-key from memory
            Array.Clear(preMKey, 0, preMKey.Length);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackageCurve25519UM1", "Manifest working key",
                workingMKey.ToHexString()));
            
            var mCryptoBytes = mCrypto.SerialiseDTO();

            // Manifest cryptography configuration has been serialised into memory, 
            // so we can now populate the SymmetricCipherConfiguration inside it to streamline things...
            mCrypto.SymmetricCipher.Key = workingMKey;

            var mHeader = new ManifestHeader {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.Curve25519UM1Hybrid.ToString(),
                    CryptographySchemeConfiguration = mCryptoBytes
                };

            WritePackage(destination, temp, mHeader, manifest, manifestCipherConfig);
        }

        /// <summary>
        /// Writes a package utillising UM1 (one-pass elliptic curve) manifest cryptography.
        /// </summary>
        /// <param name="destination">Destination stream.</param>
        /// <param name="temp">Stream location to store payload data in temporarily. May be safely destroyed after completion.</param>
        /// <param name="manifest">Manifest object describing the package contents and configuration.</param>
        /// <param name="manifestCipherConfig">Symmetric encryption cipher configuration.</param>
        /// <param name="sender">Elliptic curve cryptographic key for the sender (local user).</param>
        /// <param name="recipient">Elliptic curve cryptographic key for the recipient (remote user).</param>
        /// <param name="payloadKeys">Cryptographic keys for any items that do not have their Key field filled.</param>
        public static void WritePackageUM1Hybrid(Stream destination, Stream temp, Manifest manifest,
                                           SymmetricCipherConfiguration manifestCipherConfig, ECKeyConfiguration sender,
                                           ECKeyConfiguration recipient, Dictionary<Guid, byte[]> payloadKeys = null)
        {
            var mCrypto = new UM1ManifestCryptographyConfiguration {
                    SymmetricCipher = manifestCipherConfig,
                    KeyDerivation = CreateDefaultManifestKeyDerivation(manifestCipherConfig.KeySize / 8)
                };
            StratCom.EntropySource.NextBytes(mCrypto.KeyDerivation.Salt);

            var localPrivateKey = sender.DecodeToPrivateKey();
            var remotePublicKey = recipient.DecodeToPublicKey();

            ECPublicKeyParameters ephemeral;
            var preMKey = UM1Exchange.Initiate(remotePublicKey, localPrivateKey, out ephemeral);

            // Store the ephemeral public key in the manifest cryptography configuration
            mCrypto.EphemeralKey.EncodedKey = ECKeyUtility.Write(ephemeral.Q);

            // Generate key confirmation for manifest
            mCrypto.KeyConfirmation = ConfirmationUtility.CreateDefaultManifestKeyConfirmation(preMKey);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackageUM1Hybrid", "Manifest pre-key",
                preMKey.ToHexString()));

            var workingMKey = Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                    preMKey, mCrypto.KeyDerivation.Salt, mCrypto.SymmetricCipher.KeySize, 
                    mCrypto.KeyDerivation.SchemeConfiguration);

            // Clear the pre-key from memory
            Array.Clear(preMKey, 0, preMKey.Length);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackageUM1Hybrid", "Manifest working key",
                workingMKey.ToHexString()));

            var mCryptoBytes = mCrypto.SerialiseDTO();

            // Manifest cryptography configuration has been serialised into memory, 
            // so we can now populate the SymmetricCipherConfiguration inside it to streamline things...
            mCrypto.SymmetricCipher.Key = workingMKey;

            var mHeader = new ManifestHeader {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.UM1Hybrid.ToString(),
                    CryptographySchemeConfiguration = mCryptoBytes
                };

            // Do the handoff to the [mostly] scheme-agnostic part of the writing op
            WritePackage(destination, temp, mHeader, manifest, manifestCipherConfig);
        }

        private static KeyDerivationConfiguration CreateDefaultManifestKeyDerivation(int keyLengthBytes) {
            var schemeConfig = new ScryptConfiguration {
                    IterationPower = 16,
                    Blocks = 8,
                    Parallelism = 2
                };
            var config = new KeyDerivationConfiguration {
                    SchemeName = KeyDerivationFunctions.Scrypt.ToString(),
                    SchemeConfiguration = schemeConfig.SerialiseDTO(),
                    Salt = new byte[keyLengthBytes]
                };
            StratCom.EntropySource.NextBytes(config.Salt);
            return config;
        }

        private static void WritePackage(Stream destination, Stream payloadTemp, IManifestHeader mHeader, IManifest manifest,
                                         ISymmetricCipherConfiguration mCipherConfig) {
            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "[*PACKAGE START*] Header offset (absolute)",
                destination.Position.ToString()));

            // Write the header tag to the true destination
            destination.Write(Athena.Packaging.HeaderTagBytes, 0, Athena.Packaging.HeaderTagBytes.Length);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "Manifest header offset (absolute)",
                destination.Position.ToString()));

            // Serialise and write ManifestHeader to destination stream (this part is written as plaintext, otherwise INCEPTION!)
            StratCom.Serialiser.SerializeWithLengthPrefix(destination, mHeader, typeof (ManifestHeader),
                PrefixStyle.Base128, 0);

            /* Prepare for writing payload */

            // Check all payload items have associated key data for their encryption, supplied either in item Key field or 'payloadKeys' param.
            if (manifest.PayloadItems.Any(item => item.Encryption.Key == null || item.Encryption.Key.Length == 0)) {
                //throw new ItemKeyMissingException(item);
                throw new Exception("At least one item is missing a key.");
            }

            // Create and bind transform functions (compression, encryption, etc) defined by items' configurations to those items
            var transformFunctions = manifest.PayloadItems.Select(item => (Func<Stream, DecoratingStream>) (binding =>
                item.BindTransformStream(true, binding))).ToList();

            /* Write the payload to temporary storage (payloadTemp) */
            PayloadLayoutSchemes payloadScheme;
            try {
                payloadScheme = manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutSchemes>();
            } catch (Exception) {
                throw new PackageConfigurationException(
                    "Package payload schema specified is unsupported/unknown or missing.");
            }
            // Bind the multiplexer to the payloadTemp stream
            var mux = Source.CreatePayloadMultiplexer(payloadScheme, true, payloadTemp,
                manifest.PayloadItems.ToList<IStreamBinding>(),
                transformFunctions, manifest.PayloadConfiguration);

            mux.ExecuteAll();

            // Get internal lengths and commit them to the manifest
	        for (var i = 0; i < manifest.PayloadItems.Count; i++) {
	            manifest.PayloadItems[i].InternalLength = mux.GetItemIO(i, false);
	        }

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "Manifest working key",
                mCipherConfig.Key.ToHexString()));

            using (var manifestTemp = new MemoryStream()) {
                /* Write the manifest in encrypted form */
                using (var cs = new SymmetricCryptoStream(manifestTemp, true, mCipherConfig, null, false)) {
                    var manifestMS = StratCom.SerialiseDTO(manifest);
                    manifestMS.WriteTo(cs);
                    manifestMS.Close();
                }
                Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "Manifest length prefix offset (absolute)",
                    destination.Position.ToString()));
                destination.WritePrimitive((uint)manifestTemp.Length);
                Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "Manifest offset (absolute)",
                    destination.Position.ToString()));

                manifestTemp.WriteTo(destination);
            }

            // Clear manifest key from memory
            Array.Clear(mCipherConfig.Key, 0, mCipherConfig.Key.Length);

            // Write payload offset filler, where applicable
            if (manifest.PayloadConfiguration.Offset > 0) {
                var paddingBytes = new byte[manifest.PayloadConfiguration.Offset];
                StratCom.EntropySource.NextBytes(paddingBytes);
                destination.Write(paddingBytes, 0, paddingBytes.Length);
            }

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "Payload offset (absolute)",
                    destination.Position.ToString()));

            /* Write out payloadTemp to real destination */
            payloadTemp.Seek(0, SeekOrigin.Begin);
            payloadTemp.CopyTo(destination);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "Trailer offset (absolute)",
                    destination.Position.ToString()));

            // Write the trailer tag
            destination.Write(Athena.Packaging.TrailerTagBytes, 0, Athena.Packaging.TrailerTagBytes.Length);

            Debug.Print(DebugUtility.CreateReportString("PackageWriter", "WritePackage", "[* PACKAGE END *] Offset (absolute)",
                    destination.Position.ToString()));

            // All done! HAPPY DAYS.
            //destination.Close();
        }


        private static void CheckPackageIOIsOK(Stream destination, Manifest manifest) {
            // Can we actually perform a write to the output?
            if (!destination.CanWrite) throw new IOException("Cannot write to destination/output stream!");
            if (manifest.PayloadItems.Any(item => !item.StreamHasBinding)) {
                throw new InvalidOperationException("Internal state of package writer inconsistent. " +
                    "Stream binding and manifest counts match, but binding identifiers do not in at least one instance.");
            }
        }
    }
}
