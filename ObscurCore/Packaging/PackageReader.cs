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
using System.Threading.Tasks;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyConfirmation;
using ObscurCore.DTO;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.EllipticCurve;
using ProtoBuf;

namespace ObscurCore.Packaging
{
    public static class PackageReader
    {
        public static void SanitiseItemPaths(IEnumerable<PayloadItem> items) {
            var relUp = ".." + Path.DirectorySeparatorChar;
            if (items.Where(item => item.Type != PayloadItemTypes.KeyAction).Any(item => item.RelativePath.Contains(relUp))) {
                throw new InvalidDataException("A payload item specifies a relative path outside that of the package root. " 
                    + " This is a potentially dangerous condition.");
            }
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
				if(item.KeyConfirmation != null) {
					// We will derive the key from one supplied as a potential
					var itemKeyVerification = ConfirmationUtility.ConfirmKey (item.KeyConfirmation, payloadKeysSymmetric);
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
				throw new PackageConfigurationException(String.Format("Package payload \"{0}\" schema specified is unsupported/unknown or missing.",
				                                                      manifest.PayloadConfiguration.SchemeName));
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
			var trailerTag = new byte[Athena.Packaging.TrailerTagBytes.Length];
			source.Read (trailerTag, 0, trailerTag.Length);
			if(!trailerTag.SequenceEqual(Athena.Packaging.TrailerTagBytes)) {
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
                    if (mCryptoConfig.KeyConfirmation != null) {
                        try {
                            preMKey = ConfirmationUtility.ConfirmKey(
                                ((SymmetricManifestCryptographyConfiguration) mCryptoConfig).KeyConfirmation,
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
                
                    if (mCryptoConfig.KeyConfirmation != null) {
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
									var validationOut = ConfirmationUtility.ConfirmKey(mCryptoConfig.KeyConfirmation, new [] {ss});
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
									var validationOut = ConfirmationUtility.ConfirmKey(mCryptoConfig.KeyConfirmation, new [] {ss});
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

                    if (mCryptoConfig.KeyConfirmation != null) {
                        // See which mode (by-sender / by-recipient) is better to run in parallel
                        if (manifestKeysCurve25519Sender.Count > manifestKeysCurve25519Recipient.Count) {
                            Parallel.ForEach(manifestKeysCurve25519Sender, (sKey, state) =>
                            {
                                foreach (var rKey in manifestKeysCurve25519Recipient) {
                                    var ss = Curve25519UM1Exchange.Respond(sKey, rKey, c25519um1_ephemeralKey);
									var validationOut = ConfirmationUtility.ConfirmKey(mCryptoConfig.KeyConfirmation, new [] {ss});
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
									var validationOut = ConfirmationUtility.ConfirmKey(mCryptoConfig.KeyConfirmation, new [] {ss});
                                    if (validationOut == null) continue;
                                    preMKey = validationOut;
                                    state.Stop();
                                }
                            });
                        }
                    } else {
						// No key confirmation capability available
						if (manifestKeysCurve25519Sender.Count > 1 || manifestKeysCurve25519Recipient.Count > 1) {
							throw new KeyConfirmationException("Multiple Curve25519 keys have been provided where the package provides no key confirmation capability.");
						}
						preMKey = Curve25519UM1Exchange.Respond(manifestKeysCurve25519Sender[0], manifestKeysCurve25519Recipient[0], c25519um1_ephemeralKey);
					}
                    break;

                default:
                    throw new NotSupportedException(String.Format("Manifest cryptography scheme \"{0}\" is unsupported/unknown.", mCryptoScheme));
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
                manifest = (Manifest) StratCom.Serialiser.DeserializeWithLengthPrefix(cs, null, typeof (Manifest), PrefixStyle.Fixed32, 0);
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
            var readHeaderTag = new byte[Athena.Packaging.HeaderTagBytes.Length];
            source.Read(readHeaderTag, 0, readHeaderTag.Length);
            if (!readHeaderTag.SequenceEqual(Athena.Packaging.HeaderTagBytes)) {
                throw new InvalidDataException("Package is malformed. Expected header tag is either absent or malformed.");
            }

            var mHeader = (ManifestHeader) StratCom.Serialiser.DeserializeWithLengthPrefix(source, null, typeof (ManifestHeader),
                PrefixStyle.Base128, 0);

            if (mHeader.FormatVersion > Athena.Packaging.HeaderVersion) {
				throw new NotSupportedException(String.Format("Package version {0} as specified by the manifest header is unsupported/unknown.\n" +
					"The local version of ObscurCore supports up to version {1}.", mHeader.FormatVersion, Athena.Packaging.HeaderVersion));
                // In later versions, can redirect to diff. behaviour (and DTO objects) for diff. versions.
            }

            mCryptoScheme = mHeader.CryptographySchemeName.ToEnum<ManifestCryptographySchemes>();
            switch (mHeader.CryptographySchemeName.ToEnum<ManifestCryptographySchemes>()) {
                case ManifestCryptographySchemes.UniversalSymmetric:
                    mCryptoConfig = StratCom.DeserialiseDTO<SymmetricManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
                    break;
                case ManifestCryptographySchemes.UM1Hybrid:
                    mCryptoConfig = StratCom.DeserialiseDTO<UM1ManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
                    break;
                case ManifestCryptographySchemes.Curve25519UM1Hybrid:
                    mCryptoConfig = StratCom.DeserialiseDTO<Curve25519UM1ManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
                    break;
                default:
					throw new NotSupportedException(String.Format(
						"Package manifest cryptography scheme \"{0}\" as specified by the manifest header is unsupported/unknown.", 
				        	mHeader.CryptographySchemeName));
            }

            readOffset = (int) source.Position;

            return mHeader;
        }
    }
}
