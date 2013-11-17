using System;
using System.Collections.Generic;
using System.IO;
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
        /// Determines which (if any) key is valid from a set of potential keys, given a confirmation scheme. 
        /// Where appropriate, computes confirmations in parallel.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="potentialKeys">Set of potential keys.</param>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
        public static byte[] ConfirmKey(IVerificationFunctionConfiguration keyConfirmation,
                                                  IEnumerable<byte[]> potentialKeys)
        {
            if(keyConfirmation.VerifiedOutput == null) 
                throw new InvalidDataException("Package manifest key confirmation material is malformed. Verified output is null.");

            var validator = GetValidator(keyConfirmation);

            byte[] validatedKey = null;
            Parallel.ForEach(potentialKeys, (bytes, state) =>
                {
                    var validationOut = validator(bytes);
                    if (validationOut.SequenceEqual(keyConfirmation.VerifiedOutput)) {
                        validatedKey = validationOut;
                        // Terminate all other validation function instances - we have found the key
                        state.Stop();
                    }
                });

            // TODO: Implement a way to toggle parallelism. Current implementation wastes memory if sequential-only, due to repeated, redundant primitive newing.

            return validatedKey;
        }

        private static Func<byte[], byte[]> GetValidator(IVerificationFunctionConfiguration keyConfirmation) {
            Func<byte[], byte[]> validator; // Used as an adaptor between different validation methods
            var functionType = keyConfirmation.FunctionType.ToEnum<VerificationFunctionType>();

			if (functionType == VerificationFunctionType.KDF) {
				validator = (key) => Source.DeriveKeyWithKDF (keyConfirmation.FunctionName.ToEnum<KeyDerivationFunctions> (), 
					key, keyConfirmation.Salt, keyConfirmation.VerifiedOutput.Length, keyConfirmation.FunctionConfiguration);
			} else if (functionType == VerificationFunctionType.MAC) {
				validator = (key) => {
					var macF = Source.CreateMACPrimitive (keyConfirmation.FunctionName, key, 
					                                      keyConfirmation.Salt, keyConfirmation.FunctionConfiguration);
					if(keyConfirmation.AdditionalData != null) 
                        macF.BlockUpdate (keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
					var output = new byte[macF.GetMacSize ()];
					macF.DoFinal (output, 0);
					return output;
				};
			} else if (functionType == VerificationFunctionType.Digest) {
				validator = (key) => {
					var hashF = Source.CreateHashPrimitive (keyConfirmation.FunctionName);
                    if(keyConfirmation.Salt != null) 
                        hashF.BlockUpdate (keyConfirmation.Salt, 0, keyConfirmation.Salt.Length);
                    if(keyConfirmation.AdditionalData != null) 
                        hashF.BlockUpdate (keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
					hashF.BlockUpdate (key, 0, key.Length);
					var output = new byte[hashF.GetDigestSize ()];
					hashF.DoFinal (output, 0);
					return output;
				};
			} else {
				throw new NotSupportedException("Package manifest key confirmation scheme is unsupported/unknown.");
			}

            return validator;
        }

        public static byte[] ConfirmUM1HybridKey(IVerificationFunctionConfiguration keyConfirmation, ECKeyConfiguration ephemeralKey,
            IList<ECKeyConfiguration> manifestKeysECSender, IList<ECKeyConfiguration> manifestKeysECRecipient)
        {
             var um1SecretFunc = new Func<ECKeyConfiguration, ECKeyConfiguration, byte[]>((pubKey, privKey) =>
                        {
                            var responder = new UM1ExchangeResponder(pubKey.DecodeToPublicKey(),
                                privKey.DecodeToPrivateKey());
                            return responder.CalculateSharedSecret(ephemeralKey.DecodeToPublicKey());
                            // Run ss through key confirmation scheme and then SequenceEqual compare to hash
                        });

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

            return preKey;
        }

        public static VerificationFunctionConfiguration CreateDefaultManifestKeyConfirmation(byte[] key) {
            const VerificationFunctionType functionType = VerificationFunctionType.MAC;
            const MACFunctions macF = MACFunctions.BLAKE2B256;
            const int keySize = 16, saltSize = 16;

            var src = new VerificationFunctionConfiguration
                {
                    FunctionType = functionType.ToString(),
                    FunctionName = macF.ToString(),
                    FunctionConfiguration = null,
                    AdditionalData = functionType == VerificationFunctionType.Digest ? null : new byte[keySize],
                    Salt = functionType == VerificationFunctionType.Digest ? null : new byte[saltSize]
                };
            if (src.Salt != null) {
                StratCom.EntropySource.NextBytes(src.Salt);
            }
            if (src.AdditionalData != null) {
                StratCom.EntropySource.NextBytes(src.AdditionalData);
            }


            switch (functionType) {
                case VerificationFunctionType.Digest:
                    var hashP = Source.CreateHashPrimitive(src.FunctionName.ToEnum<HashFunctions>());

                    if (src.Salt != null) hashP.BlockUpdate(src.Salt, 0, src.Salt.Length);
                    if (src.AdditionalData != null) hashP.BlockUpdate(src.AdditionalData, 0, src.AdditionalData.Length);

                    hashP.BlockUpdate(key, 0, key.Length);
                    src.VerifiedOutput = new byte[hashP.GetDigestSize()];
                    hashP.DoFinal(src.VerifiedOutput, 0);
                    break;
                case VerificationFunctionType.MAC:
                    var macP = Source.CreateMACPrimitive(src.FunctionName.ToEnum<MACFunctions>(), key, src.Salt,
                        src.FunctionConfiguration);
                    if (src.AdditionalData != null) macP.BlockUpdate(src.AdditionalData, 0, src.AdditionalData.Length);

                    src.VerifiedOutput = new byte[macP.GetMacSize()];
                    macP.DoFinal(src.VerifiedOutput, 0);
                    break;
                case VerificationFunctionType.KDF:
                    src.VerifiedOutput = Source.DeriveKeyWithKDF(src.FunctionName.ToEnum<KeyDerivationFunctions>(), key,
                        src.Salt,
                        256, src.FunctionConfiguration);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }


            return src;
        }
    }
}
