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
using ObscurCore.Packaging;
using ProtoBuf;


namespace ObscurCore
{
    public static class StratCom
    {
		internal readonly static DTOSerialiser Serialiser = new DTOSerialiser();

        public static readonly SecureRandom EntropySource = SecureRandom.GetInstance("SHA256PRNG");

        private const int InitialSeedSize = 64; // bytes
        internal const int HeaderVersion = 1;
        internal static readonly byte[] HeaderTagBytes = Encoding.ASCII.GetBytes("OCPS-OHAI");
        internal static readonly byte[] TrailerTagBytes = Encoding.ASCII.GetBytes("OCPE-KBAI");

        static StratCom() {
            EntropySource.SetSeed(SecureRandom.GetSeed(64));
            EntropySource.SetSeed(Encoding.UTF8.GetBytes(Thread.CurrentThread.Name));
        }

        /// <summary>
		/// Provides serialisation capabilities for any object that has a ProtoContract attribute (e.g. from ObscurCore.DTO namespace).
		/// </summary>
		/// <returns>The DTO object serialised to binary data wrapped in a MemoryStream.</returns>
		public static MemoryStream SerialiseDTO(object obj, bool lengthPrefix = true) {
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
			var manifestCrypto = new UM1ManifestCryptographyConfiguration {
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
			manifestCipherConfig.Key = Source.DeriveKeyWithKDF(manifestCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
		        initiator.CalculateSharedSecret(out ephemeral), manifestCrypto.KeyDerivation.Salt,
		        manifestCrypto.SymmetricCipher.KeySize,
		        manifestCrypto.KeyDerivation.SchemeConfiguration);

			// Store the ephemeral public key in the manifest cryptography configuration object (UM1IESConfiguration)
			manifestCrypto.EphemeralKey.EncodedKey = ECKeyUtility.Write(ephemeral.Q);

			var msManifestCrypto = new MemoryStream(); // Storage for manifest cryptography configuration in serialised form
			Serialiser.Serialize(msManifestCrypto, manifestCrypto);

			var manifestHeader = new ManifestHeader() {
				FormatVersion = HeaderVersion,
				CryptographySchemeName = ManifestCryptographySchemes.UM1Hybrid.ToString(),
				CryptographySchemeConfiguration = msManifestCrypto.ToArray()
			};
			
			// Do the handoff to the [mostly] scheme-agnostic part of the writing op
			WritePackage (destination, manifestHeader, manifest, manifestCipherConfig, false);
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
			var msManifestCrypto = new MemoryStream(); // Storage for manifest cryptography configuration in serialised form

            // Derive the key which will be used for encrypting the package manifest
            var workingMKey = Source.DeriveKeyWithKDF(mCrypto.KeyDerivation.SchemeName.ToEnum<KeyDerivationFunctions>(),
                    preMKey, mCrypto.KeyDerivation.Salt, mCrypto.SymmetricCipher.KeySize,
                    mCrypto.KeyDerivation.SchemeConfiguration);

            // Clear the pre-key from memory
            Array.Clear(preMKey, 0, preMKey.Length);
			Serialiser.Serialize(msManifestCrypto, mCrypto);
            // Manifest cryptography configuration has been serialised into memory, 
            // so we can now populate the CipherConfiguration inside it to streamline things...
            mCrypto.SymmetricCipher.Key = new byte[workingMKey.Length];
            Array.Copy(workingMKey, mCrypto.SymmetricCipher.Key, workingMKey.Length);
            Array.Clear(workingMKey, 0, workingMKey.Length);
		    mCrypto.SymmetricCipher.Key = workingMKey;

            // Create the manifest header
			
			var manifestHeader = new ManifestHeader() {
				FormatVersion = HeaderVersion,
				CryptographySchemeName = ManifestCryptographySchemes.UniversalSymmetric.ToString(),
				CryptographySchemeConfiguration = msManifestCrypto.ToArray()
			};

			// Do the handoff to the [mostly] scheme-agnostic part of the writing op
			WritePackage (destination, manifestHeader, manifest, mCrypto.SymmetricCipher, false);
		}

		
        #region Core package I/O functions

        private static void WritePackage (Stream destination, ManifestHeader mHeader, IManifest manifest, 
            ISymmetricCipherConfiguration mCipherConfig, bool ies)
        {
            
            // Write the header tag
            destination.Write(HeaderTagBytes, 0, HeaderTagBytes.Length);
            // Serialise and write ManifestHeader to destination stream (this part is written as plaintext, otherwise INCEPTION!)
            Serialiser.SerializeWithLengthPrefix(destination, mHeader, typeof(ManifestHeader), PrefixStyle.Base128, 1);

			/* Write the manifest in encrypted form */

			var destinationAlias = destination;
            //if(ies) {
            //    // Get ready objects needed to compute manifest MAC
            //    var blakeMac = new Blake2BMac(512, true, true);
            //    blakeMac.Init(mCipherConfig.Key, new byte[] {0xFF} );
            //    destinationAlias = new MacStream(destination, null, blakeMac);
            //}
			using (var cs = new SymmetricCryptoStream(destinationAlias, true, mCipherConfig, null, true)) {
				Serialiser.SerializeWithLengthPrefix(cs, manifest, typeof(Manifest), PrefixStyle.Fixed32, 1);
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
				manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutSchemes> (out payloadScheme);
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