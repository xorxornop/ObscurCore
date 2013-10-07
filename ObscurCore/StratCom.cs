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
using System.Threading;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.IO;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.EllipticCurve;
using ObscurCore.Extensions.Enumerations;
using ObscurCore.Extensions.Streams;
using ObscurCore.Extensions.Generic;
using ObscurCore.Packaging;
using ProtoBuf;


namespace ObscurCore
{
    public static class StratCom
    {
		internal readonly static DTOSerialiser Serialiser = new DTOSerialiser();

        public static readonly SecureRandom EntropySource = SecureRandom.GetInstance("SHA256PRNG");

        public const int HeaderVersion = 1; // Version of DTO objects that code includes support for

        private const int InitialSeedSize = 64; // bytes
        
        internal static readonly byte[] HeaderTagBytes = Encoding.ASCII.GetBytes("OCpkg-OHAI");
        internal static readonly byte[] TrailerTagBytes = Encoding.ASCII.GetBytes("OCpkg-KBAI");

        static StratCom() {
            EntropySource.SetSeed(SecureRandom.GetSeed(InitialSeedSize));
            EntropySource.SetSeed(Encoding.UTF8.GetBytes(Thread.CurrentThread.Name));
        }

        /// <summary>
		/// Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO namespace).
		/// </summary>
		/// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
		public static MemoryStream SerialiseDTO(object obj, bool lengthPrefix = false) {
		    var type = obj.GetType();
            if (!Serialiser.CanSerializeContractType(type)) {
                throw new ArgumentException("Cannot serialise - requested object does not have a serialisation contract for its type.", "obj");
            }
            var ms = new MemoryStream();
            if (lengthPrefix) {
                Serialiser.SerializeWithLengthPrefix(ms, obj, type, PrefixStyle.Base128, 0);
            } else {
                Serialiser.Serialize(ms, obj);
            }
		    return ms;
		}

        /// <summary>
		/// Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO namespace).
		/// </summary>
		/// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
		public static T DeserialiseDTO<T>(byte[] objectBytes, bool lengthPrefix = false) {
            if (!Serialiser.CanSerializeContractType(typeof(T))) {
                throw new ArgumentException("Cannot deserialise - requested type does not have a serialisation contract.");
            }
            var ms = new MemoryStream(objectBytes);
            var outputObj = default(T);
            if (lengthPrefix) {
                outputObj = (T) Serialiser.DeserializeWithLengthPrefix(ms, outputObj, typeof (T), PrefixStyle.Base128, 0);
            } else {
                outputObj = (T) Serialiser.Deserialize(ms, outputObj, typeof (T));
            }
            return outputObj;
        }

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
		/// <param name="payloadKeys">Cryptographic keys for any items that do not have their EphemeralKey field filled with a key.</param>
		/// <param name="sender">Elliptic curve cryptographic key for the sender (local user).</param>
		/// <param name="recipient">Elliptic curve cryptographic key for the recipient (remote user).</param>
		public static void WritePackageUM1(Stream destination, Manifest manifest, SymmetricCipherConfiguration manifestCipherConfig, 
			Dictionary<Guid, byte[]> payloadKeys, ECKeyConfiguration sender, ECKeyConfiguration recipient) {

			// At the moment, we'll just force scrypt KDF and default parameters for it
			var mCrypto = new UM1ManifestCryptographyConfiguration {
				SymmetricCipher = manifestCipherConfig,
				KeyDerivation = new KeyDerivationConfiguration() {
					SchemeName = KeyDerivationFunctions.Scrypt.ToString(),
					SchemeConfiguration = ScryptConfigurationUtility.Write(ScryptConfigurationUtility.DefaultIterationPower, 
						ScryptConfigurationUtility.DefaultBlocks, ScryptConfigurationUtility.DefaultParallelisation)
				}
			};
			
			var localPrivateKey = sender.DecodeToPrivateKey();
			var remotePublicKey = recipient.DecodeToPublicKey();
			
			var initiator = new UM1ExchangeInitiator(remotePublicKey, localPrivateKey);
			ECPublicKeyParameters ephemeral;
			mCrypto.SymmetricCipher.Key = Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
		        initiator.CalculateSharedSecret(out ephemeral), mCrypto.KeyDerivation.Salt,
		        mCrypto.SymmetricCipher.KeySize,
		        mCrypto.KeyDerivation.SchemeConfiguration);

		    var mCryptoBytes = mCrypto.SerialiseDTO();

			// Store the ephemeral public key in the manifest cryptography configuration object
			mCrypto.EphemeralKey.EncodedKey = ECKeyUtility.Write(ephemeral.Q);

			var mHeader = new ManifestHeader() {
				FormatVersion = HeaderVersion,
				CryptographySchemeName = ManifestCryptographySchemes.UM1Hybrid.ToString(),
				CryptographySchemeConfiguration = mCryptoBytes
			};
			
			// Do the handoff to the [mostly] scheme-agnostic part of the writing op
			WritePackage (destination, mHeader, manifest, manifestCipherConfig, false);
		}

		/// <summary>
		/// Internal use only. Writes a package with symmetric manifest encryption - 
		/// the manifest key must be known to both parties prior to the unpackaging.
		/// </summary>
		/// <param name="destination">Destination stream.</param>
		/// <param name="manifest">Manifest object describing the package contents and configuration.</param>
		/// <param name="mCrypto">Symmetric encryption cipher configuration.</param>
		/// <param name="preMKey">Cryptographic key for the manifest encryption operation.</param>
		public static void WritePackageSymmetric(Stream destination, Manifest manifest, 
            SymmetricManifestCryptographyConfiguration mCrypto, byte[] preMKey) 
        {
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

			var mHeader = new ManifestHeader() {
				FormatVersion = HeaderVersion,
				CryptographySchemeName = ManifestCryptographySchemes.UniversalSymmetric.ToString(),
				CryptographySchemeConfiguration = mCryptoBytes
			};

			// Do the handoff to the [mostly] scheme-agnostic part of the writing op
			WritePackage (destination, mHeader, manifest, mCrypto.SymmetricCipher, false);
		}

		
        #region Core package I/O functions

        private static void WritePackage (Stream destination, ManifestHeader mHeader, IManifest manifest, 
            ISymmetricCipherConfiguration mCipherConfig, bool ies)
        {
            
            // Write the header tag
            destination.Write(HeaderTagBytes, 0, HeaderTagBytes.Length);
            // Serialise and write ManifestHeader to destination stream (this part is written as plaintext, otherwise INCEPTION!)
            Serialiser.SerializeWithLengthPrefix(destination, mHeader, typeof(ManifestHeader), PrefixStyle.Base128, 0);

			/* Write the manifest in encrypted form */

			var destinationAlias = destination;
            //if(ies) {
            //    // Get ready objects needed to compute manifest MAC
            //    var blakeMac = new Blake2BMac(512, true, true);
            //    blakeMac.Init(mCipherConfig.Key, new byte[] {0xFF} );
            //    destinationAlias = new MacStream(destination, null, blakeMac);
            //}
			using (var cs = new SymmetricCryptoStream(destinationAlias, true, mCipherConfig, null, true)) {
				Serialiser.SerializeWithLengthPrefix(cs, manifest, typeof(Manifest), PrefixStyle.Fixed32, 0);
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
				payloadScheme = manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutSchemes> ();
			} catch (Exception) {
            	throw new PackageConfigurationException("Package payload schema specified is an unknown type or missing.");
			}
            var mux = Source.CreatePayloadMultiplexer(payloadScheme, true, destination, manifest.PayloadItems.ToList<IStreamBinding>(), 
                transformFunctions, manifest.PayloadConfiguration);

			mux.ExecuteAll ();

            // Write the trailer
            destination.Write(TrailerTagBytes, 0, TrailerTagBytes.Length);
			// All done! HAPPY DAYS.
            destination.Close();
        }


        /// <summary>
        /// Read a package manifest (only) from a stream.  
        /// </summary>
        /// <param name="source">Stream to read the package from.</param>
        /// <param name="manifestKeysSymmetric">Symmetric key(s) to decrypt the manifest with.</param>
        /// <param name="manifestKeysECSender">EC public key(s) to decrypt the manifest with.</param>
        /// <param name="manifestKeysECRecipient">EC private key(s) to decrypt the manifest with.</param>
        /// <param name="readOffset">Output of number of bytes read from the source stream at method completion.</param>
        /// <returns>Package manifest object.</returns>
        private static Manifest ReadPackageManifest(Stream source, IList<byte[]> manifestKeysSymmetric, 
            IList<ECKeyConfiguration> manifestKeysECSender, IList<ECKeyConfiguration> manifestKeysECRecipient, out int readOffset) {

            readOffset = 0;
            /* Used to keep track of where we are so that, during multiple-stage package reads, we avoid errors.
             * This is useful, for example, if we wish to decrypt/unpack only *some* items in a package, rather than *all* of them.
             * Since we do not know the contents of a package prior to decrypting its Manifest, we must therefore do it in 2 stages.
             */

            IManifestCryptographySchemeConfiguration mCryptoConfig;
            ManifestCryptographySchemes mCryptoScheme;

            var mHeader = ReadPackageManifestHeader(source, out mCryptoConfig, out mCryptoScheme, out readOffset);

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
                            if (preMKey == null || preMKey.Length == 0) {
                                throw new ArgumentException(
                                    "None of the keys supplied for decryption of symmetric-cryptography-encrypted manifest was verified as being correct.",
                                        "manifestKeysSymmetric");
                            }
                        } catch (Exception e) {
                            Console.WriteLine(e);
                        }
                    } else {
                        if (manifestKeysSymmetric.Count > 1) {
                            throw new ArgumentException("Multiple viable symmetric keys have been provided where the package provides no key confirmation.", 
                                "manifestKeysSymmetric");
                        }
                        preMKey = manifestKeysSymmetric[0];
                    }
                    break;
                case ManifestCryptographySchemes.UM1Hybrid: {
                    // Identify matching public-private key pairs based on curve provider and curve name
                    var ephemeralKey = ((UM1ManifestCryptographyConfiguration) mCryptoConfig).EphemeralKey;
                    ECKeyConfiguration preKeyLocal = null;

                    var secretFunc = new Func<ECKeyConfiguration, ECKeyConfiguration, ECKeyConfiguration, byte[]>
                        ((pubKey, privKey, ephKey) => 
                            {
                                var responder = new UM1ExchangeResponder(pubKey.DecodeToPublicKey(), privKey.DecodeToPrivateKey());
                                return responder.CalculateSharedSecret(ephKey.DecodeToPublicKey());
                            });
                
                    if (mCryptoConfig.KeyVerification != null) {
                        // Find which one is the right one (at great computational cost!)
                        var viableSenderKeys =
                        manifestKeysECSender.Where(key => key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                            key.CurveName.Equals(ephemeralKey.CurveName));

                        foreach (var senderKey in from senderKey in viableSenderKeys 
                                                  from recipientKey in manifestKeysECRecipient 
                                                  where (preMKey = secretFunc(senderKey, recipientKey, ephemeralKey))
                            .SequenceEqual(mCryptoConfig.KeyVerification.Hash) select senderKey) {
                            goto confirmed;
                        }
                        throw new ArgumentException("No provided EC keys were able to be confirmed as able to decrypt the manifest.");
                    }

                    if (manifestKeysECSender.Count > 1 || manifestKeysECRecipient.Count > 1) {
                        throw new ArgumentException("Multiple EC keys have been provided where the package provides no key confirmation.");
                    }

                    preMKey = secretFunc(manifestKeysECSender[0], manifestKeysECRecipient[0], ephemeralKey);
                }
                    break;
                default:
                    throw new NotSupportedException("Manifest cryptography scheme " + mCryptoScheme + " is not supported.");
            }

            confirmed:
            // Derive the working manifest key
            var workingMKey = Source.DeriveKeyWithKDF(mCryptoConfig.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                    preMKey, mCryptoConfig.KeyDerivation.Salt, mCryptoConfig.SymmetricCipher.KeySize,
                    mCryptoConfig.KeyDerivation.SchemeConfiguration);

            var mCipherConfig = DeserialiseDTO<SymmetricCipherConfiguration>(mHeader.CryptographySchemeConfiguration);

            Manifest manifest = null;

            using (var cs = new SymmetricCryptoStream(source, true, mCipherConfig, workingMKey, true)) {
                manifest = (Manifest) Serialiser.DeserializeWithLengthPrefix(cs, null, typeof (Manifest), PrefixStyle.Fixed32, 0);
            }

            readOffset = (int) source.Position;
            return manifest;
        }


        private static ManifestHeader ReadPackageManifestHeader(Stream source, out IManifestCryptographySchemeConfiguration mCryptoConfig,
            out ManifestCryptographySchemes mCryptoScheme, out int readOffset) {

            var readHeaderTag = new byte[HeaderTagBytes.Length];
            source.Read(readHeaderTag, 0, readHeaderTag.Length);

            if (!readHeaderTag.SequenceEqual(HeaderTagBytes)) {
                throw new InvalidDataException("Package is malformed. Header tag is either absent or malformed.");
            }

            var mHeader = (ManifestHeader) Serialiser.DeserializeWithLengthPrefix(source, null, typeof (ManifestHeader),
                PrefixStyle.Base128, 0);

            if (mHeader.FormatVersion > HeaderVersion) {
                throw new NotSupportedException("Version of this package is unsupported. Cannot proceed.");
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
                default:
                    throw new ArgumentOutOfRangeException();
            }

            readOffset = (int) source.Position;

            return mHeader;
        }

        #endregion

        private static byte[] ConfirmSymmetricKey(KeyConfirmationConfiguration keyConfirmation,
                                                  IEnumerable<byte[]> potentialKeys) {
            Func<byte[], byte[], byte[]> validateFunc = null; // Used as an adaptor between different validation methods
            // TODO: Write adaptor methods for confirmation methods

            return (from potentialKey in potentialKeys let checkhash = validateFunc(potentialKey, keyConfirmation.Salt) 
                    where checkhash.SequenceEqual(keyConfirmation.Hash) select potentialKey).FirstOrDefault();
        }


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