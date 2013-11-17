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
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyConfirmation;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.EllipticCurve;
using ProtoBuf;

// This code file contains all StratCom functionality relating to packaging/unpackaging.

namespace ObscurCore.Packaging
{
    public static class PackageWriter
    {
        private static void CheckPackageIOIsOK(Stream destination, Manifest manifest) {
            // Can we actually perform a write to the output?
            if (!destination.CanWrite) throw new IOException("Cannot write to destination/output stream!");
            if (manifest.PayloadItems.Any(item => !item.StreamHasBinding)) {
                throw new InvalidOperationException("Internal state of package writer inconsistent. " +
                    "Stream binding and manifest counts match, but binding identifiers do not in at least one instance.");
            }
        }

        /// <summary>
        /// Writes a package utillising UM1 (one-pass elliptic curve) manifest cryptography.
        /// </summary>
        /// <param name="destination">Destination stream.</param>
        /// <param name="manifest">Manifest object describing the package contents and configuration.</param>
        /// <param name="manifestCipherConfig">Symmetric encryption cipher configuration.</param>
        /// <param name="sender">Elliptic curve cryptographic key for the sender (local user).</param>
        /// <param name="recipient">Elliptic curve cryptographic key for the recipient (remote user).</param>
        /// <param name="payloadKeys">Cryptographic keys for any items that do not have their Key field filled.</param>
        public static void WritePackageUM1(Stream destination, Manifest manifest,
                                           SymmetricCipherConfiguration manifestCipherConfig, ECKeyConfiguration sender,
                                           ECKeyConfiguration recipient, Dictionary<Guid, byte[]> payloadKeys = null)
        {
            // At the moment, we'll just force scrypt KDF and default parameters for it
            var mCrypto = new UM1ManifestCryptographyConfiguration
                {
                    SymmetricCipher = manifestCipherConfig,
                    KeyDerivation = new KeyDerivationConfiguration()
                        {
                            SchemeName = KeyDerivationFunctions.Scrypt.ToString(),
                            SchemeConfiguration =
                                ScryptConfigurationUtility.Write(ScryptConfigurationUtility.DefaultIterationPower,
                                    ScryptConfigurationUtility.DefaultBlocks,
                                    ScryptConfigurationUtility.DefaultParallelisation)
                        }
                };
            StratCom.EntropySource.NextBytes(mCrypto.KeyDerivation.Salt);

            var localPrivateKey = sender.DecodeToPrivateKey();
            var remotePublicKey = recipient.DecodeToPublicKey();

            var initiator = new UM1ExchangeInitiator(remotePublicKey, localPrivateKey);
            ECPublicKeyParameters ephemeral;
            mCrypto.SymmetricCipher.Key =
                Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                    initiator.CalculateSharedSecret(out ephemeral), mCrypto.KeyDerivation.Salt,
                    mCrypto.SymmetricCipher.KeySize,
                    mCrypto.KeyDerivation.SchemeConfiguration);

            // Store the ephemeral public key in the manifest cryptography configuration object
            mCrypto.EphemeralKey.EncodedKey = ECKeyUtility.Write(ephemeral.Q);

            var mHeader = new ManifestHeader()
                {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.UM1Hybrid.ToString(),
                    CryptographySchemeConfiguration = mCrypto.SerialiseDTO()
                };

            // Do the handoff to the [mostly] scheme-agnostic part of the writing op
            WritePackage(destination, mHeader, manifest, manifestCipherConfig);
        }

        /// <summary>
        /// Writes a package utillising Curve25519-based UM1 (one-pass elliptic curve) manifest cryptography.
        /// </summary>
        /// <param name="destination">Destination stream.</param>
        /// <param name="manifest">Manifest object describing the package contents and configuration.</param>
        /// <param name="manifestCipherConfig">Symmetric encryption cipher configuration.</param>
        /// <param name="sender">Elliptic curve cryptographic key for the sender (local user).</param>
        /// <param name="recipient">Elliptic curve cryptographic key for the recipient (remote user).</param>
        /// <param name="payloadKeys">Cryptographic keys for any items that do not have their Key field filled.</param>
        public static void WritePackageCurve25519UM1(Stream destination, Manifest manifest,
                                                     SymmetricCipherConfiguration manifestCipherConfig,
                                                     byte[] sender, byte[] recipient,
                                                     Dictionary<Guid, byte[]> payloadKeys = null) {
            if (sender.Length != 32) {
                throw new ArgumentException(
                    "Sender's Curve25519 elliptic curve private key is not 32 bytes in length.", "sender");
            }
            if (recipient.Length != 32) {
                throw new ArgumentException(
                    "Recipient's Curve25519 elliptic curve public key is not 32 bytes in length.", "recipient");
            }

            // At the moment, we'll just force scrypt KDF and default parameters for it
            var mCrypto = new UM1ManifestCryptographyConfiguration
                {
                    SymmetricCipher = manifestCipherConfig,
                    KeyDerivation = new KeyDerivationConfiguration()
                        {
                            SchemeName = KeyDerivationFunctions.Scrypt.ToString(),
                            SchemeConfiguration =
                                ScryptConfigurationUtility.Write(ScryptConfigurationUtility.DefaultIterationPower,
                                    ScryptConfigurationUtility.DefaultBlocks,
                                    ScryptConfigurationUtility.DefaultParallelisation)
                        }
                };
            StratCom.EntropySource.NextBytes(mCrypto.KeyDerivation.Salt);

            byte[] ephemeral;
            mCrypto.SymmetricCipher.Key =
                Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                    Curve25519UM1Exchange.Initiate(recipient, sender, out ephemeral), mCrypto.KeyDerivation.Salt,
                    mCrypto.SymmetricCipher.KeySize,
                    mCrypto.KeyDerivation.SchemeConfiguration);

            // Clear the manifest source/pre-keys from memory
            Array.Clear(sender, 0, sender.Length);
            Array.Clear(recipient, 0, recipient.Length);

            // Store the ephemeral public key in the manifest cryptography configuration object
            mCrypto.EphemeralKey.EncodedKey = ephemeral;

            var mHeader = new ManifestHeader()
                {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.Curve25519UM1Hybrid.ToString(),
                    CryptographySchemeConfiguration = mCrypto.SerialiseDTO()
                };

            WritePackage(destination, mHeader, manifest, manifestCipherConfig);
        }

        /// <summary>
        /// Internal use only. Writes a package with symmetric manifest encryption - 
        /// the manifest key must be known to both parties prior to the unpackaging.
        /// </summary>
        /// <param name="destination">Destination stream.</param>
        /// <param name="manifest">Manifest object describing the package contents and configuration.</param>
        /// <param name="manifestCipherConfig">Symmetric encryption cipher configuration.</param>
        /// <param name="preMKey">Cryptographic key for the manifest encryption operation (after further derivation).</param>
        /// <param name="payloadKeys">Cryptographic keys for any items that do not have their Key field filled.</param>
        public static void WritePackageSymmetric(Stream destination, Manifest manifest,
                                                 SymmetricCipherConfiguration manifestCipherConfig, byte[] preMKey,
                                                 bool confirm = true, Dictionary<Guid, byte[]> payloadKeys = null) {
            // At the moment, we'll just force scrypt KDF and default parameters for it
            var mCrypto = new SymmetricManifestCryptographyConfiguration()
                {
                    SymmetricCipher = manifestCipherConfig,
                    KeyDerivation = CreateDefaultManifestKeyDerivation(preMKey.Length)
                };
            if (confirm) mCrypto.KeyConfirmation = ConfirmationUtility.CreateDefaultManifestKeyConfirmation(preMKey);

            // Derive the key which will be used for encrypting the package manifest
            var workingMKey = Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                preMKey, mCrypto.KeyDerivation.Salt, mCrypto.SymmetricCipher.KeySize,
                mCrypto.KeyDerivation.SchemeConfiguration);

            // Clear the pre-key from memory
            Array.Clear(preMKey, 0, preMKey.Length);

            var mCryptoBytes = mCrypto.SerialiseDTO();

            // Manifest cryptography configuration has been serialised into memory, 
            // so we can now populate the SymmetricCipherConfiguration inside it to streamline things...
            mCrypto.SymmetricCipher.Key = new byte[workingMKey.Length];
            Array.Copy(workingMKey, mCrypto.SymmetricCipher.Key, workingMKey.Length);
            Array.Clear(workingMKey, 0, workingMKey.Length);

            var mHeader = new ManifestHeader()
                {
                    FormatVersion = Athena.Packaging.HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.UniversalSymmetric.ToString(),
                    CryptographySchemeConfiguration = mCryptoBytes
                };

            WritePackage(destination, mHeader, manifest, mCrypto.SymmetricCipher);
        }

        

        private static KeyDerivationConfiguration CreateDefaultManifestKeyDerivation(int keyLengthBytes) {
            var schemeConfig = new ScryptConfiguration()
                {
                    IterationPower = 16,
                    Blocks = 8,
                    Parallelism = 2
                };

            var src = new KeyDerivationConfiguration()
                {
                    SchemeName = KeyDerivationFunctions.Scrypt.ToString(),
                    SchemeConfiguration = schemeConfig.SerialiseDTO(),
                    Salt = new byte[keyLengthBytes]
                };
            StratCom.EntropySource.NextBytes(src.Salt);
            return src;
        }


        private static void WritePackage(Stream destination, ManifestHeader mHeader, IManifest manifest,
                                         ISymmetricCipherConfiguration mCipherConfig) {
            // Write the header tag
            destination.Write(Athena.Packaging.HeaderTagBytes, 0, Athena.Packaging.HeaderTagBytes.Length);
            // Serialise and write ManifestHeader to destination stream (this part is written as plaintext, otherwise INCEPTION!)
            StratCom.Serialiser.SerializeWithLengthPrefix(destination, mHeader, typeof (ManifestHeader),
                PrefixStyle.Base128, 0);

            /* Write the manifest in encrypted form */

            using (var cs = new SymmetricCryptoStream(destination, true, mCipherConfig, null, true)) {
                StratCom.Serialiser.SerializeWithLengthPrefix(cs, manifest, typeof (Manifest), PrefixStyle.Fixed32, 0);
            }

            // Clear manifest key from memory
            Array.Clear(mCipherConfig.Key, 0, mCipherConfig.Key.Length);

            /* Prepare for writing payload */

            // Check all payload items have associated key data for their encryption, supplied either in item Key field or 'payloadKeys' param.
            if (manifest.PayloadItems.Any(
                item => item.Encryption.Key == null || item.Encryption.Key.Length == 0)) {
                //throw new ItemKeyMissingException(item);
                throw new Exception("At least one item is missing a key.");
            }

            // Create and bind transform functions (compression, encryption, etc) defined by items' configurations to those items
            var transformFunctions = manifest.PayloadItems.Select(item => (Func<Stream, DecoratingStream>) (binding =>
                item.BindTransformStream(true, binding))).ToList();

            /* Write the payload */

            PayloadLayoutSchemes payloadScheme;
            try {
                payloadScheme = manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutSchemes>();
            } catch (Exception) {
                throw new PackageConfigurationException(
                    "Package payload schema specified is unsupported/unknown or missing.");
            }
            var mux = Source.CreatePayloadMultiplexer(payloadScheme, true, destination,
                manifest.PayloadItems.ToList<IStreamBinding>(),
                transformFunctions, manifest.PayloadConfiguration);

            mux.ExecuteAll();

            // Write the trailer
            destination.Write(Athena.Packaging.TrailerTagBytes, 0, Athena.Packaging.TrailerTagBytes.Length);
            // All done! HAPPY DAYS.
            //destination.Close();
        }
    }
}
