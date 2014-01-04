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
using System.Linq;
using System.Threading.Tasks;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.Support;
using ObscurCore.DTO;
using ObscurCore.Extensions.EllipticCurve;

namespace ObscurCore.Cryptography.KeyConfirmation
{
    /// <summary>
    /// Provides convenience methods for confirming cryptographic keys.
    /// </summary>
    public static class ConfirmationUtility
    {
        /// <summary>
        /// Determines which (if any) key is valid from a set of potential keys. 
        /// Where appropriate, computes confirmations in parallel.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="ephemeralKey">Ephemeral key in the agreement.</param>
        /// <param name="manifestKeysECSender">Set of potential sender keys.</param>
        /// <param name="manifestKeysECRecipient">Set of potential receiver keys.</param>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
		/// <exception cref="ArgumentNullException">Any of the supplied parameters are null.</exception>
		/// <exception cref="ArgumentException">
		/// Curve provider and/or name of all key components do not match, 
		/// or either/both of the sender/receiver enumerations are of zero length.
		/// </exception>
		/// <exception cref="ConfigurationValueInvalidException">
		/// Confirmation configuration has an invalid element.
		/// </exception>
        public static byte[] ConfirmUM1HybridKey(IVerificationFunctionConfiguration keyConfirmation, EcKeyConfiguration ephemeralKey,
			IEnumerable<EcKeyConfiguration> senderKeys, IEnumerable<EcKeyConfiguration> receiverKeys)
        {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
			} else if (ephemeralKey == null) {
				throw new ArgumentNullException("ephemeralKey", "No ephemeral key supplied.");
			} else if (senderKeys == null) {
				throw new ArgumentNullException("senderKeys", "No potential sender keys supplied.");
			} else if (receiverKeys == null) {
				throw new ArgumentNullException("receiverKeys", "No potential receiver keys supplied.");
			}

            // We can determine which, if any, of the provided keys are capable of decrypting the manifest
            var viableSenderKeys =
				senderKeys.Where(key => key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                key.CurveName.Equals(ephemeralKey.CurveName)).ToList();
			if (viableSenderKeys.Count == 0) {
				throw new ArgumentException (
					"No viable sender keys found - curve provider and/or curve name do not match ephemeral key.", "senderKeys");
			}

			var viableReceiverKeys =
				receiverKeys.Where(key => key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                key.CurveName.Equals(ephemeralKey.CurveName)).ToList();
			if (viableReceiverKeys.Count == 0) {
				throw new ArgumentException (
					"No viable receiver keys found - curve provider and/or curve name do not match ephemeral key.", "receiverKeys");
			}

            var validator = GetValidator(keyConfirmation);
			var um1SecretFunc = new Func<EcKeyConfiguration, EcKeyConfiguration, byte[]>((pubKey, privKey) => 
				UM1Exchange.Respond(pubKey.DecodeToPublicKey(), privKey.DecodeToPrivateKey(), ephemeralKey.DecodeToPublicKey()));

			byte[] preKey = null;

            // See which mode (by-sender / by-recipient) is better to run in parallel
			if (viableSenderKeys.Count > viableReceiverKeys.Count) {
                Parallel.ForEach(viableSenderKeys, (sKey, state) =>
                    {
						foreach (var rKey in viableReceiverKeys) {
                            var ss = um1SecretFunc(sKey, rKey);
                            var validationOut = validator(ss);
                            if (validationOut.SequenceEqual(keyConfirmation.VerifiedOutput)) {
                                preKey = ss;
                                state.Stop();
                            }
                        }
                    });
            } else {
				Parallel.ForEach(viableReceiverKeys, (rKey, state) =>
                    {
                        foreach (var sKey in viableSenderKeys) {
                            var ss = um1SecretFunc(sKey, rKey);
                            var validationOut = validator(ss);
                            if (validationOut.SequenceEqual(keyConfirmation.VerifiedOutput)) {
                                preKey = ss;
                                state.Stop();
                            }
                        }
                    });
            }

            Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "ConfirmUM1HybridKey", "Key output", 
                preKey != null ? preKey.ToHexString() : "[null]"));
            return preKey;
        }

        /// <summary>
        /// Determines which (if any) key is valid from a set of potential keys. 
        /// Where appropriate, computes confirmations in parallel.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="ephemeralKey">Ephemeral key in the agreement.</param>
        /// <param name="manifestKeysCurve25519Sender">Set of potential sender keys.</param>
        /// <param name="manifestKeysCurve25519Receiver">Set of potential receiver keys.</param>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
		/// <exception cref="ArgumentNullException">Any of the parameters is null.</exception>
		/// <exception cref="ArgumentException">
		/// Sender or receiver key enumerations are of zero length.
		/// </exception>
		/// <exception cref="ConfigurationValueInvalidException">
		/// Confirmation configuration has an invalid element.
		/// </exception>
        public static byte[] ConfirmCurve25519UM1HybridKey(IVerificationFunctionConfiguration keyConfirmation, byte[] ephemeralKey,
			IEnumerable<byte[]> senderKeys, IEnumerable<byte[]> receiverKeys)
        {
			if (keyConfirmation == null) {
				throw new ArgumentNullException ("keyConfirmation", "No configuration supplied.");
			} else if (senderKeys == null) {
				throw new ArgumentNullException ("ephemeralKey", "No ephemeral key supplied.");
			} else if (senderKeys == null) {
				throw new ArgumentNullException("senderKeys", "No potential sender keys supplied.");
			} else if(receiverKeys == null) {
				throw new ArgumentNullException("receiverKeys", "No potential receiver keys supplied.");
            }

            // See which mode (by-sender / by-recipient) is better to run in parallel
			var keysCurve25519Sender = senderKeys as IList<byte[]> ?? senderKeys.ToList();
			if(keysCurve25519Sender.Count == 0) {
				throw new ArgumentException ("No potential sender keys supplied.", "senderKeys");
			}
			var keysCurve25519Recipient = receiverKeys as IList<byte[]> ?? receiverKeys.ToList();
			if(keysCurve25519Sender.Count == 0) {
				throw new ArgumentException ("No potential receiver keys supplied.", "receiverKeys");
			}

			var validator = GetValidator(keyConfirmation);
			byte[] preKey = null;

            if (keysCurve25519Sender.Count() > keysCurve25519Recipient.Count()) {
                Parallel.ForEach(keysCurve25519Sender, (sKey, state) =>
                    {
                        foreach (var rKey in keysCurve25519Recipient) {
                            var ss = Curve25519UM1Exchange.Respond(sKey, rKey, ephemeralKey);
                            var validationOut = validator(ss);
                            if (validationOut.SequenceEqual(keyConfirmation.VerifiedOutput)) {
                                preKey = ss;
                                state.Stop();
                            }
                        }
                    });
            } else {
                Parallel.ForEach(keysCurve25519Recipient, (rKey, state) =>
                    {
                        foreach (var sKey in keysCurve25519Sender) {
                            var ss = Curve25519UM1Exchange.Respond(sKey, rKey, ephemeralKey);
                            var validationOut = validator(ss);
                            if (validationOut.SequenceEqual(keyConfirmation.VerifiedOutput)) {
                                preKey = ss;
                                state.Stop();
                            }
                        }
                    });
            }

            Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "ConfirmCurve25519UM1HybridKey", "Key output", 
                preKey != null ? preKey.ToHexString() : "[null]"));
            return preKey;
        }

        /// <summary>
        /// Determines which (if any) key is valid from a set of potential keys. 
        /// Where appropriate, computes confirmations in parallel.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="potentialKeys">Set of potential keys.</param>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
        public static byte[] ConfirmSymmetricKey(IVerificationFunctionConfiguration keyConfirmation, IEnumerable<byte[]> potentialKeys) {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
            }
            if (potentialKeys == null) {
                throw new ArgumentNullException("potentialKeys", "No potential keys supplied.");
            }
            var validator = GetValidator(keyConfirmation);
            byte[] preKey = null;

            Parallel.ForEach(potentialKeys, (key, state) =>
                {
                    var validationOut = validator(key);
                    if (validationOut.SequenceEqual(keyConfirmation.VerifiedOutput)) {
                        preKey = key;
                        // Terminate all other validation function instances - we have found the key
                        state.Stop();
                    }
                });

            Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "ConfirmSymmetricKey", "Key output", 
                preKey != null ? preKey.ToHexString() : "[null]"));
            return preKey;
        }

		/// <summary>
		/// Gets a validation function that returns the output of a configured verification method.
		/// </summary>
		/// <returns>Callable validation function.</returns>
		/// <param name="keyConfirmation">Key confirmation configuration defining validation method to be employed.</param>
		/// <exception cref="ConfigurationValueInvalidException">
		/// Some aspect of configuration invalid - detailed inside exception message.
		/// </exception>
        private static Func<byte[], byte[]> GetValidator(IVerificationFunctionConfiguration keyConfirmation) {
			VerificationFunctionType functionType;
			try {
				functionType = keyConfirmation.FunctionType.ToEnum<VerificationFunctionType> ();
			} catch (EnumerationValueUnknownException ex) {
				throw new ConfigurationValueInvalidException ("Verification function type is unsupported/unknown.", ex);
			}

			if (functionType == VerificationFunctionType.None) {
				throw new ConfigurationValueInvalidException ("Verification function type cannot be None.");
			} else if (String.IsNullOrEmpty(keyConfirmation.FunctionName)) {
				throw new ConfigurationValueInvalidException ("Verification function name cannot be null or empty.");
			}

            Func<byte[], byte[]> validator; // Used as an adaptor between different validation methods
			switch (functionType) {
				case VerificationFunctionType.Kdf:
					KeyDerivationFunction kdfEnum;
					try {
						kdfEnum = keyConfirmation.FunctionName.ToEnum<KeyDerivationFunction> ();
					} catch (EnumerationValueUnknownException ex) {
						throw new ConfigurationValueInvalidException ("Key derivation function is unsupported/unknown.", ex);
					}
					validator = (key) => Source.DeriveKeyWithKdf (kdfEnum, key, keyConfirmation.Salt, 
						keyConfirmation.VerifiedOutput.Length, keyConfirmation.FunctionConfiguration);
			        break;
			    case VerificationFunctionType.Mac:
					MacFunction macFEnum;
					try {
						macFEnum = keyConfirmation.FunctionName.ToEnum<MacFunction> ();
					} catch (EnumerationValueUnknownException ex) {
						throw new ConfigurationValueInvalidException ("Key derivation function is unsupported/unknown.", ex);
					}
			        validator = (key) => {
						var macF = Source.CreateMacPrimitive (macFEnum, key, keyConfirmation.Salt, 
							keyConfirmation.FunctionConfiguration);
			            if(!keyConfirmation.AdditionalData.IsNullOrZeroLength()) 
			                macF.BlockUpdate (keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
			            var output = new byte[macF.MacSize];
			            macF.DoFinal (output, 0);
			            return output;
			        };
			        break;
			    case VerificationFunctionType.Digest:
				HashFunction hashFEnum;
					try {
						hashFEnum = keyConfirmation.FunctionName.ToEnum<HashFunction> ();
					} catch (EnumerationValueUnknownException ex) {
						throw new ConfigurationValueInvalidException ("Hash/digest function is unsupported/unknown.", ex);
					}
					validator = (key) => {
					var hashF = Source.CreateHashPrimitive (hashFEnum);
			            if(!keyConfirmation.Salt.IsNullOrZeroLength()) 
			                hashF.BlockUpdate (keyConfirmation.Salt, 0, keyConfirmation.Salt.Length);
			            if(!keyConfirmation.AdditionalData.IsNullOrZeroLength()) 
			                hashF.BlockUpdate (keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
			            hashF.BlockUpdate (key, 0, key.Length);
			            var output = new byte[hashF.DigestSize];
			            hashF.DoFinal (output, 0);
			            return output;
			        };
			        break;
			    default:
					throw new NotImplementedException();
			}

            return validator;
        }

		/// <summary>
		/// Creates a default manifest key confirmation. 
		/// Uses BLAKE2B-256 with random salt and additional data, currently.
		/// </summary>
		/// <returns>A key confirmation as a verification configuration.</returns>
		/// <param name="key">Key to confirm. Constitutes key prior to key derivation.</param>
		/// <exception cref="ArgumentException">Key is null or zero-length.</exception>
        public static VerificationFunctionConfiguration CreateDefaultManifestKeyConfirmation(byte[] key) {
			// TODO: Turn this method into a factory-type, using optional default values 
            const VerificationFunctionType functionType = VerificationFunctionType.Mac;
			// Used when their respective type is selected (defaults)
			const HashFunction hashFEnum = HashFunction.Blake2B256;
			const MacFunction macFEnum = MacFunction.Blake2B256;
			const KeyDerivationFunction kdfEnum = KeyDerivationFunction.Scrypt;
			const int minimumOutputSizeBytes = 16;

			if (key.IsNullOrZeroLength()) {
				throw new ArgumentException ("Key is null or zero-length.", "key");
			}

			string functionName;

			int saltSize = 0;
			switch (functionType) {
				case VerificationFunctionType.Digest:
					functionName = hashFEnum.ToString();
					saltSize = Athena.Cryptography.HashFunctions[hashFEnum].OutputSize / 8;
					break;
				case VerificationFunctionType.Mac:
					functionName = macFEnum.ToString();
					var macFOutputSize = Athena.Cryptography.MacFunctions [macFEnum].OutputSize;
					saltSize = (macFOutputSize ?? minimumOutputSizeBytes) / 8;
					break;
				case VerificationFunctionType.Kdf:
					functionName = kdfEnum.ToString();
					saltSize = minimumOutputSizeBytes;
					break;
				default:
					throw new NotImplementedException ();
			}

            var config = new VerificationFunctionConfiguration
                {
                    FunctionType = functionType.ToString(),
					FunctionName = functionName,
                    FunctionConfiguration = null
                };

            // Add entropy
            // if (functionType != VerificationFunctionType.Digest) {
            if (true) {
                config.Salt = new byte[saltSize];
                StratCom.EntropySource.NextBytes(config.Salt);
            }

            switch (functionType) {
                case VerificationFunctionType.Digest:
                    var hashP = Source.CreateHashPrimitive(config.FunctionName.ToEnum<HashFunction>());
                    if (config.Salt != null) hashP.BlockUpdate(config.Salt, 0, config.Salt.Length);
                    if (config.AdditionalData != null) hashP.BlockUpdate(config.AdditionalData, 0, config.AdditionalData.Length);
                    hashP.BlockUpdate(key, 0, key.Length);
                    config.VerifiedOutput = new byte[hashP.DigestSize];
                    hashP.DoFinal(config.VerifiedOutput, 0);
                    break;
                case VerificationFunctionType.Mac:
                    var macP = Source.CreateMacPrimitive(config.FunctionName.ToEnum<MacFunction>(), key, config.Salt,
                        config.FunctionConfiguration);
                    if (config.AdditionalData != null) macP.BlockUpdate(config.AdditionalData, 0, config.AdditionalData.Length);
                    config.VerifiedOutput = new byte[macP.MacSize];
                    macP.DoFinal(config.VerifiedOutput, 0);
                    break;
                case VerificationFunctionType.Kdf:
                    config.VerifiedOutput = Source.DeriveKeyWithKdf(config.FunctionName.ToEnum<KeyDerivationFunction>(), key,
						config.Salt, 32, config.FunctionConfiguration);
                    break;
            }

			Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "CreateDefaultManifestKeyConfirmation", "Verified output", 
                config.VerifiedOutput.ToHexString()));

            return config;
        }
    }
}
