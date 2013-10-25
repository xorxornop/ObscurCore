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
using System.Threading.Tasks;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.EllipticCurve;
using ObscurCore.Packaging;
using ProtoBuf;

// This code file contains all StratCom functionality relating to packaging/unpackaging.

namespace ObscurCore
{
    public static partial class StratCom
    {
        internal const int HeaderVersion = 1; // Version of DTO objects that code includes support for

        internal static readonly byte[] HeaderTagBytes = Encoding.ASCII.GetBytes("OCpkg-OHAI");
        internal static readonly byte[] TrailerTagBytes = Encoding.ASCII.GetBytes("KBAI-OCpkg");


        private static void CheckPackageIOIsOK(Stream destination, Manifest manifest) {
			// Can we actually perform a write to the output?
			if (!destination.CanWrite) throw new IOException("Cannot write to destination/output stream!");
			if (manifest.PayloadItems.Any(item => !item.StreamHasBinding)) {
				throw new InvalidOperationException("Internal state of package writer inconsistent. " +
				                                    "Stream binding and manifest counts match, but binding identifiers do not in at least one instance.");
			}
		}


        #region Writing

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
                                           ECKeyConfiguration recipient, Dictionary<Guid, byte[]> payloadKeys = null) {

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
            EntropySource.NextBytes(mCrypto.KeyDerivation.Salt);

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
                    FormatVersion = HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.UM1Hybrid.ToString(),
                    CryptographySchemeConfiguration = mCrypto.SerialiseDTO()
                };

            // Do the handoff to the [mostly] scheme-agnostic part of the writing op
            WritePackage(destination, mHeader, manifest, manifestCipherConfig, false);
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
            EntropySource.NextBytes(mCrypto.KeyDerivation.Salt);

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
                    FormatVersion = HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.Curve25519UM1Hybrid.ToString(),
                    CryptographySchemeConfiguration = mCrypto.SerialiseDTO()
                };

            WritePackage(destination, mHeader, manifest, manifestCipherConfig, false);
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
                                                 Dictionary<Guid, byte[]> payloadKeys = null)
        {
            // At the moment, we'll just force scrypt KDF and default parameters for it
            var mCrypto = new SymmetricManifestCryptographyConfiguration()
                {
                    SymmetricCipher = manifestCipherConfig,
                    KeyDerivation = new KeyDerivationConfiguration()
                        {
                            SchemeName = KeyDerivationFunctions.Scrypt.ToString(),
                            SchemeConfiguration =
                                ScryptConfigurationUtility.Write(ScryptConfigurationUtility.DefaultIterationPower,
                                    ScryptConfigurationUtility.DefaultBlocks,
                                    ScryptConfigurationUtility.DefaultParallelisation),
                        }
                };
            mCrypto.KeyDerivation.Salt = new byte[preMKey.Length];
            EntropySource.NextBytes(mCrypto.KeyDerivation.Salt);
            
            // Derive the key which will be used for encrypting the package manifest
            var workingMKey = Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                preMKey, mCrypto.KeyDerivation.Salt, mCrypto.SymmetricCipher.KeySize,
                mCrypto.KeyDerivation.SchemeConfiguration);

            // Clear the pre-key from memory
            Array.Clear(preMKey, 0, preMKey.Length);

            var mCryptoBytes = mCrypto.SerialiseDTO();

            // Manifest cryptography configuration has been serialised into memory, 
            // so we can now populate the CipherConfiguration inside it to streamline things...
            mCrypto.SymmetricCipher.Key = new byte[workingMKey.Length];
            Array.Copy(workingMKey, mCrypto.SymmetricCipher.Key, workingMKey.Length);
            Array.Clear(workingMKey, 0, workingMKey.Length);

            var mHeader = new ManifestHeader()
                {
                    FormatVersion = HeaderVersion,
                    CryptographySchemeName = ManifestCryptographySchemes.UniversalSymmetric.ToString(),
                    CryptographySchemeConfiguration = mCryptoBytes
                };

            WritePackage(destination, mHeader, manifest, mCrypto.SymmetricCipher, false);
        }


        private static void WritePackage(Stream destination, ManifestHeader mHeader, IManifest manifest,
                                         ISymmetricCipherConfiguration mCipherConfig, bool ies) 
        {
            // Write the header tag
            destination.Write(HeaderTagBytes, 0, HeaderTagBytes.Length);
            // Serialise and write ManifestHeader to destination stream (this part is written as plaintext, otherwise INCEPTION!)
            Serialiser.SerializeWithLengthPrefix(destination, mHeader, typeof (ManifestHeader), PrefixStyle.Base128, 0);

            /* Write the manifest in encrypted form */

            var destinationAlias = destination;
            //if(ies) {
            //    // Get ready objects needed to compute manifest MAC
            //    var blakeMac = new Blake2BMac(512, true, true);
            //    blakeMac.Init(mCipherConfig.Key, new byte[] {0xFF} );
            //    destinationAlias = new MacStream(destination, null, blakeMac);
            //}
            using (var cs = new SymmetricCryptoStream(destinationAlias, true, mCipherConfig, null, true)) {
                Serialiser.SerializeWithLengthPrefix(cs, manifest, typeof (Manifest), PrefixStyle.Fixed32, 0);
            }
            //// At the moment, IES is forced to use BLAKE2B only, but need to create a DTO object to detail MAC configurations
            //if(ies) {
            //    // Write manifest MAC & optional tag
            //    var mac = ((MacStream)destinationAlias).WriteMac() as Blake2BMac;

            //    var output = new byte[mac.GetMacSize()];
            //    mac.DoFinal(output, 0);
            //    // Write the MAC
            //    destination.Write(output, 0, output.Length);
            //}
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
                    "Package payload schema specified is an unknown type or missing.");
            }
            var mux = Source.CreatePayloadMultiplexer(payloadScheme, true, destination,
                manifest.PayloadItems.ToList<IStreamBinding>(),
                transformFunctions, manifest.PayloadConfiguration);

            mux.ExecuteAll();

            // Write the trailer
            destination.Write(TrailerTagBytes, 0, TrailerTagBytes.Length);
            // All done! HAPPY DAYS.
            //destination.Close();
        }

        #endregion


        #region Reading


        public static void SanitiseItemPaths(IEnumerable<PayloadItem> items) {
            var relUp = ".." + Path.DirectorySeparatorChar;
            if (items.Where(item => item.Type != PayloadItemTypes.KeyAction).Any(item => item.RelativePath.Contains(relUp))) {
                throw new InvalidDataException("A payload item specifies a relative path outside that of the package root. " 
                    + " This is a potentially dangerous condition.");
            }
        }

        public static void ReadPackageToFiles() {
            
        }

        
        /// <summary>
		/// Reads a package payload.
		/// </summary>
		/// <param name="source">Stream to read the package from.</param>
		/// <param name="manifest">Manifest.</param>
		/// <param name="readOffset">How many bytes have already been read from the stream. 
		/// Set to null to use Stream.Position</param>
		/// <param name="payloadKeysSymmetric">Potential symmetric keys for payload items.</param>
		public static void ReadPackagePayload(Stream source, IManifest manifest, int? readOffset = null, 
		                                       IList<byte[]> payloadKeysSymmetric = null)
        {
			if (readOffset == null)
				readOffset = (int) source.Position;
			// Seek to current offset (end of manifest) plus the payload [frameshift] offset, where applicable
			if (source.Position != readOffset)
				source.Seek ((long)readOffset + manifest.PayloadOffset, SeekOrigin.Begin);

			// Check that all payload items have decryption keys - if they do not, derive them
			foreach(var item in manifest.PayloadItems) {
				if(item.KeyVerification != null) {
					// We will derive the key from one supplied as a potential
					var itemKeyVerification = ConfirmSymmetricKey (item.KeyVerification, payloadKeysSymmetric);
					if (itemKeyVerification == null || itemKeyVerification.Length == 0) {
						//throw new ArgumentException(
							//"None of the keys supplied for decryption of payload items were verified as being correct.",
							//"payloadKeysSymmetric");
						throw new ItemKeyMissingException (item);
					}
				} else {
					if(item.Encryption.Key != null) {
						throw new ItemKeyMissingException (item);
					}
				}
			}

			// Create and bind transform functions (compression, encryption, etc) defined by items' configurations to those items
			var transformFunctions = manifest.PayloadItems.Select(item => (Func<Stream, DecoratingStream>) 
				(binding => item.BindTransformStream(true, binding))).ToList();

			// Read the payload
			PayloadLayoutSchemes payloadScheme;
			try {
				payloadScheme = manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutSchemes> ();
			} catch (Exception) {
				throw new PackageConfigurationException("Package payload schema specified is an unknown type or missing.");
			}
			var mux = Source.CreatePayloadMultiplexer(payloadScheme, true, source, manifest.PayloadItems.ToList<IStreamBinding>(), 
			                                          transformFunctions, manifest.PayloadConfiguration);

			// Demux the payload
			try {
				mux.ExecuteAll ();
			} catch (Exception ex) {
				// Catch different kinds of exception in future
				throw ex;
			}

			// Read the trailer
			var trailerTag = new byte[TrailerTagBytes.Length];
			source.Read (trailerTag, 0, trailerTag.Length);
			if(!trailerTag.SequenceEqual(TrailerTagBytes)) {
				throw new InvalidDataException("Package is malformed. Trailer tag is either absent or malformed." 
				                               + "It would appear, however, that the package has unpacked successfully despite this.");
			}
		}


        /// <summary>
        /// Read a package manifest (only) from a stream.  
        /// </summary>
        /// <remarks>
        /// Call method, supplying (all of) only the keys associated with the sender and the context. 
        /// This both maximises the chance that 1) the package will be successfully decrypted if multiple 
        /// keys are in use by both parties, and 2) minimise the time spent validating potential key pairs.
        /// </remarks>
        /// <param name="source">Stream to read the package from.</param>
        /// <param name="manifestKeysSymmetric">Symmetric key(s) to decrypt the manifest with.</param>
        /// <param name="manifestKeysECSender">EC public key(s) to decrypt the manifest with.</param>
        /// <param name="manifestKeysECRecipient">EC private key(s) to decrypt the manifest with.</param>
        /// <param name="manifestKeysCurve25519Sender">Curve25519 EC public key(s) to decrypt the manifest with.</param>
        /// <param name="manifestKeysCurve25519Recipient">Curve25519 EC private key(s) to decrypt the manifest with.</param>
        /// <param name="readOffset">Output of number of bytes read from the source stream at method completion.</param>
        /// <returns>Package manifest object.</returns>
        public static Manifest ReadPackageManifest(Stream source, IList<byte[]> manifestKeysSymmetric, 
            IList<ECKeyConfiguration> manifestKeysECSender, IList<ECKeyConfiguration> manifestKeysECRecipient, 
            IList<byte[]> manifestKeysCurve25519Sender, IList<byte[]> manifestKeysCurve25519Recipient, out int readOffset) {

            /* 
             * readOffset is used to keep track of where we are so that, during multiple-stage package reads, we avoid errors.
             * This is useful, for example, if we wish to decrypt/unpack only *some* items in a package, rather than *all* of them.
             * Since we do not know the contents of a package prior to decrypting its Manifest, we must therefore do it in 2 stages.
             */

            IManifestCryptographySchemeConfiguration mCryptoConfig;
            ManifestCryptographySchemes mCryptoScheme;
            var mHeader = ReadPackageManifestHeader(source, out mCryptoConfig, out mCryptoScheme, out readOffset);

            // Determine the pre-key for the package manifest decryption (different schemes use different approaches)
            byte[] preMKey = null;
            switch (mCryptoScheme) {
                case ManifestCryptographySchemes.UniversalSymmetric:
                    if (manifestKeysSymmetric.Count == 0) {
                        throw new ArgumentException("No keys supplied for decryption of symmetric-cryptography-encrypted manifest.", 
                            "manifestKeysSymmetric");
                    }
                    if (mCryptoConfig.KeyVerification != null) {
                        try {
                            preMKey = ConfirmSymmetricKey(
                                ((SymmetricManifestCryptographyConfiguration) mCryptoConfig).KeyVerification,
                                manifestKeysSymmetric);
                        } catch (Exception e) {
                            throw new KeyConfirmationException("Key confirmation failed in an unexpected way.", e);
                        }
                    } else {
                        if (manifestKeysSymmetric.Count > 1) {
                            throw new ArgumentException("Multiple symmetric keys have been provided where the package provides no key confirmation capability.", 
                                "manifestKeysSymmetric");
                        }
                        preMKey = manifestKeysSymmetric[0];
                    }
                    break;

                case ManifestCryptographySchemes.UM1Hybrid:
                    // Identify matching public-private key pairs based on curve provider and curve name
                    var um1_ephemeralKey = ((UM1ManifestCryptographyConfiguration) mCryptoConfig).EphemeralKey;

                    var um1SecretFunc = new Func<ECKeyConfiguration, ECKeyConfiguration, byte[]>((pubKey, privKey) =>
                        {
                            var responder = new UM1ExchangeResponder(pubKey.DecodeToPublicKey(),
                                privKey.DecodeToPrivateKey());
                            return responder.CalculateSharedSecret(um1_ephemeralKey.DecodeToPublicKey());
                            // Run ss through key confirmation scheme and then SequenceEqual compare to hash
                        });
                
                    if (mCryptoConfig.KeyVerification != null) {
                        // We can determine which, if any, of the provided keys are capable of decrypting the manifest
                        var viableSenderKeys =
                        manifestKeysECSender.Where(key => key.CurveProviderName.Equals(um1_ephemeralKey.CurveProviderName) &&
                            key.CurveName.Equals(um1_ephemeralKey.CurveName)).ToList();
                        var viableRecipientKeys =
                        manifestKeysECRecipient.Where(key => key.CurveProviderName.Equals(um1_ephemeralKey.CurveProviderName) &&
                            key.CurveName.Equals(um1_ephemeralKey.CurveName)).ToList();

                        // See which mode (by-sender / by-recipient) is better to run in parallel
                        if (viableSenderKeys.Count > viableRecipientKeys.Count) {
                            Parallel.ForEach(viableSenderKeys, (sKey, state) =>
                            {
                                foreach (var rKey in viableRecipientKeys) {
                                    var ss = um1SecretFunc(sKey, rKey);
                                    var validationOut = ConfirmSymmetricKey(mCryptoConfig.KeyVerification, ss);
                                    if (validationOut == null) continue;
                                    preMKey = validationOut;
                                    state.Stop();
                                }
                            });
                        } else {
                            Parallel.ForEach(viableRecipientKeys, (rKey, state) =>
                            {
                                foreach (var sKey in viableSenderKeys) {
                                    var ss = um1SecretFunc(sKey, rKey);
                                    var validationOut = ConfirmSymmetricKey(mCryptoConfig.KeyVerification, ss);
                                    if (validationOut == null) continue;
                                    preMKey = validationOut;
                                    state.Stop();
                                }
                            });
                        }
                    } else {
						// No key confirmation capability available
						if (manifestKeysECSender.Count > 1 || manifestKeysECRecipient.Count > 1) {
							throw new KeyConfirmationException("Multiple EC keys have been provided where the package provides no key confirmation capability.");
						}
						preMKey = um1SecretFunc(manifestKeysECSender[0], manifestKeysECRecipient[0]);
					}
                    break;

                case ManifestCryptographySchemes.Curve25519UM1Hybrid:

                    var c25519um1_ephemeralKey = ((Curve25519UM1ManifestCryptographyConfiguration) mCryptoConfig).EphemeralKey;

                    if (mCryptoConfig.KeyVerification != null) {
                        // See which mode (by-sender / by-recipient) is better to run in parallel
                        if (manifestKeysCurve25519Sender.Count > manifestKeysCurve25519Recipient.Count) {
                            Parallel.ForEach(manifestKeysCurve25519Sender, (sKey, state) =>
                            {
                                foreach (var rKey in manifestKeysCurve25519Recipient) {
                                    var ss = Curve25519UM1Exchange.Respond(sKey, rKey, c25519um1_ephemeralKey);
                                    var validationOut = ConfirmSymmetricKey(mCryptoConfig.KeyVerification, ss);
                                    if (validationOut == null) continue;
                                    preMKey = validationOut;
                                    state.Stop();
                                }
                            });
                        } else {
                            Parallel.ForEach(manifestKeysCurve25519Recipient, (rKey, state) =>
                            {
                                foreach (var sKey in manifestKeysCurve25519Sender) {
                                    var ss = Curve25519UM1Exchange.Respond(sKey, rKey, c25519um1_ephemeralKey);
                                    var validationOut = ConfirmSymmetricKey(mCryptoConfig.KeyVerification, ss);
                                    if (validationOut == null) continue;
                                    preMKey = validationOut;
                                    state.Stop();
                                }
                            });
                        }
                    } else {
						// No key confirmation capability available
						if (manifestKeysECSender.Count > 1 || manifestKeysECRecipient.Count > 1) {
							throw new KeyConfirmationException("Multiple Curve25519 keys have been provided where the package provides no key confirmation capability.");
						}
						preMKey = Curve25519UM1Exchange.Respond(manifestKeysCurve25519Sender[0], manifestKeysCurve25519Recipient[0], c25519um1_ephemeralKey);
					}
                    break;

                default:
                    throw new NotSupportedException(String.Format("Manifest cryptography scheme {0} is unsupported/unknown.", mCryptoScheme));
            }

            if (preMKey == null || preMKey.Length == 0) {
                throw new KeyConfirmationException(String.Format(
                    "None of the keys provided to decrypt the manifest (cryptographic scheme: {0}) were confirmed as being able to do so.", mCryptoScheme));
            }

            // Derive the working manifest key
            var workingMKey = Source.DeriveKeyWithKDF(mCryptoConfig.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                    preMKey, mCryptoConfig.KeyDerivation.Salt, mCryptoConfig.SymmetricCipher.KeySize,
                    mCryptoConfig.KeyDerivation.SchemeConfiguration);

            Manifest manifest = null;

            using (var cs = new SymmetricCryptoStream(source, true, mCryptoConfig.SymmetricCipher, workingMKey, true)) {
                manifest = (Manifest) Serialiser.DeserializeWithLengthPrefix(cs, null, typeof (Manifest), PrefixStyle.Fixed32, 0);
                readOffset += (int) cs.BytesOut;
            }

            return manifest;
        }

		/// <summary>
		/// Reads a package manifest header (only) from a stream.
		/// </summary>
		/// <param name="source">Stream to read the header from.</param>
		/// <param name="mCryptoConfig">Manifest cryptography configuration deserialised from the header.</param>
		/// <param name="mCryptoScheme">Manifest cryptography scheme parsed from the header.</param>
		/// <param name="readOffset">Output of number of bytes read from the source stream at method completion.</param>
		/// <returns>Package manifest header object.</returns>
        public static ManifestHeader ReadPackageManifestHeader(Stream source, out IManifestCryptographySchemeConfiguration mCryptoConfig,
            out ManifestCryptographySchemes mCryptoScheme, out int readOffset)
        {
            var readHeaderTag = new byte[HeaderTagBytes.Length];
            source.Read(readHeaderTag, 0, readHeaderTag.Length);
            if (!readHeaderTag.SequenceEqual(HeaderTagBytes)) {
                throw new InvalidDataException("Package is malformed. Expected header tag is either absent or malformed.");
            }

            var mHeader = (ManifestHeader) Serialiser.DeserializeWithLengthPrefix(source, null, typeof (ManifestHeader),
                PrefixStyle.Base128, 0);

            if (mHeader.FormatVersion > HeaderVersion) {
                throw new NotSupportedException("Package version " + mHeader.FormatVersion + " as specified by the manifest header is unsupported/unknown.\n" +
                    "The local version of ObscurCore supports up to version " + HeaderVersion + ".");
                // In later versions, can redirect to diff. behaviour (and DTO objects) for diff. versions.
            }

            mCryptoScheme = mHeader.CryptographySchemeName.ToEnum<ManifestCryptographySchemes>();
            switch (mHeader.CryptographySchemeName.ToEnum<ManifestCryptographySchemes>()) {
                case ManifestCryptographySchemes.UniversalSymmetric:
                    mCryptoConfig = DeserialiseDTO<SymmetricManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
                    break;
                case ManifestCryptographySchemes.UM1Hybrid:
                    mCryptoConfig = DeserialiseDTO<UM1ManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
                    break;
                case ManifestCryptographySchemes.Curve25519UM1Hybrid:
                    mCryptoConfig = DeserialiseDTO<Curve25519UM1ManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            readOffset = (int) source.Position;

            return mHeader;
        }

        /// <summary>
        /// Determines which (if any) key is valid from a set of potential keys, given a confirmation scheme.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="potentialKeys">Set of potential keys.</param>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
        private static byte[] ConfirmSymmetricKey(IKeyConfirmationConfiguration keyConfirmation,
                                                  IEnumerable<byte[]> potentialKeys)
        {
            byte[] validatedKey = null;
            Parallel.ForEach(potentialKeys, (bytes, state) =>
                {
                    var validationOut = ConfirmSymmetricKey(keyConfirmation, bytes);
                    if (validationOut.SequenceEqual(keyConfirmation.Hash)) {
                        validatedKey = validationOut;
                        // Terminate all other validation function instances - we have found the key
                        state.Stop();
                    }
                });

            return validatedKey;
        }

        /// <summary>
        /// Determines if a provided key is validated successfully with a given key confirmation scheme.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="potentialKey">Potential key to be validated.</param>
        /// <returns>Valid key, or null if not validated as being correct.</returns>
        private static byte[] ConfirmSymmetricKey(IKeyConfirmationConfiguration keyConfirmation, byte[] potentialKey) {
            Func<byte[], byte[], byte[]> validator = null; // Used as an adaptor between different validation methods
            // Signature is: key, salt, returns validation output byte[]

            if (Enum.GetNames(typeof (KeyDerivationFunctions)).Contains(keyConfirmation.SchemeName)) {
                validator =
                    (key, salt) => Source.DeriveKeyWithKDF(keyConfirmation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                        key, salt, keyConfirmation.Hash.Length, keyConfirmation.SchemeConfiguration);
            } else {
                throw new NotSupportedException("Package manifest key confirmation scheme is unsupported/unknown.");
            }

            return validator(potentialKey, keyConfirmation.Salt);
        }

        #endregion

    }

    /// <summary>
	/// Represents the error that occurs when, during package I/O, 
	/// cryptographic key material associated with a payload item cannot be found. 
	/// </summary>
	public class ItemKeyMissingException : Exception
	{
		public ItemKeyMissingException (PayloadItem item) : base 
			(String.Format("A cryptographic key for item GUID {0} and relative path \"{1}\" could not be found.", 
			                item.Identifier.ToString(), item.RelativePath))
		{}
	}

    public class KeyConfirmationException : Exception
    {
        public KeyConfirmationException() {}
        public KeyConfirmationException(string message) : base(message) {}
        public KeyConfirmationException(string message, Exception inner) : base(message, inner) {}
    }

    /// <summary>
	/// Represents the error that occurs when, during package I/O, 
	/// a configuration error causes an abort of the package I/O operation.
	/// </summary>
	public class PackageConfigurationException : Exception
	{
		public PackageConfigurationException (string message) : base(message)
		{
		}
	}
}
