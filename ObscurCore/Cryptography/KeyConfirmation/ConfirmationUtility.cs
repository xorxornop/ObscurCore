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
using ObscurCore.Cryptography.KeyAgreement.Primitives;
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
        public static byte[] ConfirmUM1HybridKey(IVerificationFunctionConfiguration keyConfirmation, EcKeyConfiguration ephemeralKey,
            IEnumerable<EcKeyConfiguration> manifestKeysECSender, IEnumerable<EcKeyConfiguration> manifestKeysECRecipient)
        {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
            }
            if (manifestKeysECSender == null) {
                throw new ArgumentNullException("manifestKeysECSender", "No potential sender keys supplied.");
            } else if(manifestKeysECRecipient == null) {
                throw new ArgumentNullException("manifestKeysECRecipient", "No potential receiver keys supplied.");
            }

             var um1SecretFunc = new Func<EcKeyConfiguration, EcKeyConfiguration, byte[]>((pubKey, privKey) => 
                 UM1Exchange.Respond(pubKey.DecodeToPublicKey(), privKey.DecodeToPrivateKey(), ephemeralKey.DecodeToPublicKey()));

            byte[] preKey = null;

            // We can determine which, if any, of the provided keys are capable of decrypting the manifest
            var viableSenderKeys =
            manifestKeysECSender.Where(key => key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                key.CurveName.Equals(ephemeralKey.CurveName)).ToList();
            var viableRecipientKeys =
            manifestKeysECRecipient.Where(key => key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                key.CurveName.Equals(ephemeralKey.CurveName)).ToList();

            var validator = GetValidator(keyConfirmation);

            // See which mode (by-sender / by-recipient) is better to run in parallel
            if (viableSenderKeys.Count > viableRecipientKeys.Count) {
                Parallel.ForEach(viableSenderKeys, (sKey, state) =>
                    {
                        foreach (var rKey in viableRecipientKeys) {
                            var ss = um1SecretFunc(sKey, rKey);
                            var validationOut = validator(ss);
                            if (validationOut == null) continue;
                            preKey = validationOut;
                            state.Stop();
                        }
                    });
            } else {
                Parallel.ForEach(viableRecipientKeys, (rKey, state) =>
                {
                    foreach (var sKey in viableSenderKeys) {
                        var ss = um1SecretFunc(sKey, rKey);
						var validationOut = validator(ss);
                        if (validationOut == null) continue;
                        preKey = validationOut;
                        state.Stop();
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
        public static byte[] ConfirmCurve25519UM1HybridKey(IVerificationFunctionConfiguration keyConfirmation, byte[] ephemeralKey,
            IEnumerable<byte[]> manifestKeysCurve25519Sender, IEnumerable<byte[]> manifestKeysCurve25519Receiver)
        {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
            }
            if (manifestKeysCurve25519Sender == null) {
                throw new ArgumentNullException("manifestKeysCurve25519Sender", "No potential sender keys supplied.");
            } else if(manifestKeysCurve25519Receiver == null) {
                throw new ArgumentNullException("manifestKeysCurve25519Receiver", "No potential receiver keys supplied.");
            }

            byte[] preKey = null;
            var validator = GetValidator(keyConfirmation);
            // See which mode (by-sender / by-recipient) is better to run in parallel
            var keysCurve25519Sender = manifestKeysCurve25519Sender as IList<byte[]> ?? manifestKeysCurve25519Sender.ToList();
            var keysCurve25519Recipient = manifestKeysCurve25519Receiver as IList<byte[]> ?? manifestKeysCurve25519Receiver.ToList();
            if (keysCurve25519Sender.Count() > keysCurve25519Recipient.Count()) {
                Parallel.ForEach(keysCurve25519Sender, (sKey, state) =>
                {
                    foreach (var rKey in keysCurve25519Recipient) {
                        var ss = Curve25519UM1Exchange.Respond(sKey, rKey, ephemeralKey);
                        var validationOut = validator(ss);
                        if (validationOut == null) continue;
                        preKey = validationOut;
                        state.Stop();
                    }
                });
            } else {
                Parallel.ForEach(keysCurve25519Recipient, (rKey, state) =>
                {
                    foreach (var sKey in keysCurve25519Sender) {
                        var ss = Curve25519UM1Exchange.Respond(sKey, rKey, ephemeralKey);
						var validationOut = validator(ss);
                        if (validationOut == null) continue;
                        preKey = validationOut;
                        state.Stop();
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

        private static Func<byte[], byte[]> GetValidator(IVerificationFunctionConfiguration keyConfirmation) {
            Func<byte[], byte[]> validator; // Used as an adaptor between different validation methods
            var functionType = keyConfirmation.FunctionType.ToEnum<VerificationFunctionType>();

			switch (functionType) {
			    case VerificationFunctionType.Kdf:
			        validator = (key) => Source.DeriveKeyWithKdf (keyConfirmation.FunctionName.ToEnum<KeyDerivationFunction> (), 
			            key, keyConfirmation.Salt, keyConfirmation.VerifiedOutput.Length, keyConfirmation.FunctionConfiguration);
			        break;
			    case VerificationFunctionType.Mac:
			        validator = (key) => {
			            var macF = Source.CreateMacPrimitive (keyConfirmation.FunctionName.ToEnum<MacFunction> (), key, 
			                keyConfirmation.Salt, keyConfirmation.FunctionConfiguration);
			            if(!keyConfirmation.AdditionalData.IsNullOrZeroLength()) 
			                macF.BlockUpdate (keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
			            var output = new byte[macF.MacSize];
			            macF.DoFinal (output, 0);
			            return output;
			        };
			        break;
			    case VerificationFunctionType.Digest:
			        validator = (key) => {
			            var hashF = Source.CreateHashPrimitive (keyConfirmation.FunctionName.ToEnum<HashFunction> ());
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
			        throw new NotSupportedException("Package manifest key confirmation scheme is unsupported/unknown.");
			}

            return validator;
        }

        public static VerificationFunctionConfiguration CreateDefaultManifestKeyConfirmation(byte[] key) {
            const VerificationFunctionType functionType = VerificationFunctionType.Mac;
            const MacFunction macF = MacFunction.Blake2B256;
            const int saltSize = 16;

            var config = new VerificationFunctionConfiguration
                {
                    FunctionType = functionType.ToString(),
                    FunctionName = macF.ToString(),
                    FunctionConfiguration = null
                };
            if (functionType != VerificationFunctionType.Digest) {
                config.Salt = new byte[saltSize];
                StratCom.EntropySource.NextBytes(config.Salt);
            }
            if (functionType != VerificationFunctionType.Digest) {
                config.AdditionalData = new byte[key.Length];
                StratCom.EntropySource.NextBytes(config.AdditionalData);
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
                        config.Salt,
                        256, config.FunctionConfiguration);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "CreateDefaultManifestKeyConfirmation", ".VerifiedOutput", 
                config.VerifiedOutput.ToHexString()));

            return config;
        }
    }
}
