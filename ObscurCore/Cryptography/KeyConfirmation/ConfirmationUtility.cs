using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.DTO;
using ObscurCore.Extensions.ByteArrays;
using ObscurCore.Extensions.EllipticCurve;

namespace ObscurCore.Cryptography.KeyConfirmation
{
    /// <summary>
    /// Provides convenience methods for confirming cryptographic keys.
    /// </summary>
    public static class ConfirmationUtility
    {
        private static Func<byte[], byte[]> GetValidator(IVerificationFunctionConfiguration keyConfirmation) {
            Func<byte[], byte[]> validator; // Used as an adaptor between different validation methods
            var functionType = keyConfirmation.FunctionType.ToEnum<VerificationFunctionType>();

			switch (functionType) {
			    case VerificationFunctionType.KDF:
			        validator = (key) => Source.DeriveKeyWithKdf (keyConfirmation.FunctionName.ToEnum<KeyDerivationFunction> (), 
			            key, keyConfirmation.Salt, keyConfirmation.VerifiedOutput.Length, keyConfirmation.FunctionConfiguration);
			        break;
			    case VerificationFunctionType.MAC:
			        validator = (key) => {
			            var macF = Source.CreateMacPrimitive (keyConfirmation.FunctionName.ToEnum<MacFunction> (), key, 
			                keyConfirmation.Salt, keyConfirmation.FunctionConfiguration);
			            if(keyConfirmation.AdditionalData != null) 
			                macF.BlockUpdate (keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
			            var output = new byte[macF.MacSize];
			            macF.DoFinal (output, 0);
			            return output;
			        };
			        break;
			    case VerificationFunctionType.Digest:
			        validator = (key) => {
			            var hashF = Source.CreateHashPrimitive (keyConfirmation.FunctionName.ToEnum<HashFunction> ());
			            if(keyConfirmation.Salt != null) 
			                hashF.BlockUpdate (keyConfirmation.Salt, 0, keyConfirmation.Salt.Length);
			            if(keyConfirmation.AdditionalData != null) 
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

        public static byte[] ConfirmUM1HybridKey(IVerificationFunctionConfiguration keyConfirmation, ECKeyConfiguration ephemeralKey,
            IList<ECKeyConfiguration> manifestKeysECSender, IList<ECKeyConfiguration> manifestKeysECRecipient)
        {
             var um1SecretFunc = new Func<ECKeyConfiguration, ECKeyConfiguration, byte[]>((pubKey, privKey) => 
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

            Debug.Print("[ConfirmUM1HybridKey] : " + (preKey != null ? preKey.ToHexString() : "[null] (no key found)"));
            return preKey;
        }

        public static byte[] ConfirmCurve25519UM1HybridKey(IVerificationFunctionConfiguration keyConfirmation,
                                                 byte[] ephemeralKey,
                                                 IList<byte[]> manifestKeysCurve25519Sender,
                                                 IList<byte[]> manifestKeysCurve25519Recipient)
        {
            byte[] preKey = null;
            var validator = GetValidator(keyConfirmation);
            // See which mode (by-sender / by-recipient) is better to run in parallel
            if (manifestKeysCurve25519Sender.Count > manifestKeysCurve25519Recipient.Count) {
                Parallel.ForEach(manifestKeysCurve25519Sender, (sKey, state) =>
                {
                    foreach (var rKey in manifestKeysCurve25519Recipient) {
                        var ss = Curve25519UM1Exchange.Respond(sKey, rKey, ephemeralKey);
                        var validationOut = validator(ss);
                        if (validationOut == null) continue;
                        preKey = validationOut;
                        state.Stop();
                    }
                });
            } else {
                Parallel.ForEach(manifestKeysCurve25519Recipient, (rKey, state) =>
                {
                    foreach (var sKey in manifestKeysCurve25519Sender) {
                        var ss = Curve25519UM1Exchange.Respond(sKey, rKey, ephemeralKey);
						var validationOut = validator(ss);
                        if (validationOut == null) continue;
                        preKey = validationOut;
                        state.Stop();
                    }
                });
            }

            Debug.Print("[ConfirmCurve25519UM1HybridKey] : " + (preKey != null ? preKey.ToHexString() : "[null] (no key found)"));
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

            Debug.Print("[ConfirmSymmetricKey] : " + (preKey != null ? preKey.ToHexString() : "[null] (no key found)"));
            return preKey;
        }

        public static VerificationFunctionConfiguration CreateDefaultManifestKeyConfirmation(byte[] key) {
            const VerificationFunctionType functionType = VerificationFunctionType.MAC;
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
                case VerificationFunctionType.MAC:
                    var macP = Source.CreateMacPrimitive(config.FunctionName.ToEnum<MacFunction>(), key, config.Salt,
                        config.FunctionConfiguration);
                    if (config.AdditionalData != null) macP.BlockUpdate(config.AdditionalData, 0, config.AdditionalData.Length);

                    config.VerifiedOutput = new byte[macP.MacSize];
                    macP.DoFinal(config.VerifiedOutput, 0);
                    break;
                case VerificationFunctionType.KDF:
                    config.VerifiedOutput = Source.DeriveKeyWithKdf(config.FunctionName.ToEnum<KeyDerivationFunction>(), key,
                        config.Salt,
                        256, config.FunctionConfiguration);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            Debug.Print("[CreateDefaultManifestKeyConfirmation] .VerifiedOutput: " + config.VerifiedOutput.ToHexString());

            return config;
        }
    }
}
