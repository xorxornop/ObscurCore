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
using System.Text;
using System.Threading.Tasks;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyConfirmation
{
    /// <summary>
    ///     Provides convenience methods for confirming cryptographic keys.
    /// </summary>
    public static class ConfirmationUtility
    {
        internal static readonly byte[] TagConstantBytes = Encoding.UTF8.GetBytes("OBSCURCORE_KC");

        /// <summary>
        ///     Generate a verified output of a function given the correct key, to be used as a key confirmation.
        /// </summary>
        /// <param name="configuration">Configuration of the verification function.</param>
        /// <param name="key">Key to generate a confirmation output verification for.</param>
        /// <returns>Output of the verification function, given the correct key.</returns>
        /// <exception cref="ArgumentException">Key is null or zero-length.</exception>
        public static byte[] GenerateVerifiedOutput(AuthenticationFunctionConfiguration configuration, byte[] key)
        {
            if (key.IsNullOrZeroLength()) {
                throw new ArgumentException("Key is null or zero-length.", "key");
            }

            Func<byte[], byte[]> validator = GetValidator(configuration, TagConstantBytes, configuration.SerialiseDto());
            byte[] verifiedOutput = validator(key);

            Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "GenerateVerifiedOutput",
                "Verified output",
                verifiedOutput.ToHexString()));

            return verifiedOutput;
        }

        /// <summary>
        ///     Determines which (if any) key is valid from a set of potential keys.
        ///     Where appropriate, computes confirmations in parallel.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="verifiedOutput">Output of verification function, given the correct key.</param>
        /// <param name="ephemeralKey">Ephemeral key in the agreement.</param>
        /// <param name="senderKeys">Set of potential sender keys.</param>
        /// <param name="receiverKeys">Set of potential receiver keys.</param>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
        /// <exception cref="ArgumentNullException">Any of the supplied parameters are null.</exception>
        /// <exception cref="ArgumentException">
        ///     Curve provider and/or name of all key components do not match,
        ///     or either/both of the sender/receiver enumerations are of zero length.
        /// </exception>
        /// <exception cref="ConfigurationInvalidException">
        ///     Confirmation configuration has an invalid element.
        /// </exception>
        public static byte[] ConfirmUm1HybridKey(AuthenticationFunctionConfiguration keyConfirmation,
            byte[] verifiedOutput,
            EcKeyConfiguration ephemeralKey, IEnumerable<EcKeyConfiguration> senderKeys,
            IEnumerable<EcKeyConfiguration> receiverKeys)
        {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
            }
            if (ephemeralKey == null) {
                throw new ArgumentNullException("ephemeralKey", "No ephemeral key supplied.");
            }
            if (senderKeys == null) {
                throw new ArgumentNullException("senderKeys", "No potential sender keys supplied.");
            }
            if (receiverKeys == null) {
                throw new ArgumentNullException("receiverKeys", "No potential receiver keys supplied.");
            }

            // We can determine which, if any, of the provided keys are capable of decrypting the manifest
            List<EcKeyConfiguration> viableSenderKeys =
                senderKeys.Where(key => key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                                        key.CurveName.Equals(ephemeralKey.CurveName)).ToList();
            if (viableSenderKeys.Count == 0) {
                throw new ArgumentException(
                    "No viable sender keys found - curve provider and/or curve name do not match ephemeral key.",
                    "senderKeys");
            }

            List<EcKeyConfiguration> viableReceiverKeys =
                receiverKeys.Where(key => key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                                          key.CurveName.Equals(ephemeralKey.CurveName)).ToList();
            if (viableReceiverKeys.Count == 0) {
                throw new ArgumentException(
                    "No viable receiver keys found - curve provider and/or curve name do not match ephemeral key.",
                    "receiverKeys");
            }

            Func<byte[], byte[]> validator = GetValidator(keyConfirmation, TagConstantBytes,
                keyConfirmation.SerialiseDto(), verifiedOutput.Length);
            var um1SecretFunc = new Func<EcKeyConfiguration, EcKeyConfiguration, byte[]>((pubKey, privKey) =>
                Um1Exchange.Respond(pubKey, privKey, ephemeralKey));

            byte[] preKey = null;

            // See which mode (by-sender / by-recipient) is better to run in parallel
            if (viableSenderKeys.Count > viableReceiverKeys.Count) {
                Parallel.ForEach(viableSenderKeys, (sKey, state) => {
                    foreach (EcKeyConfiguration rKey in viableReceiverKeys) {
                        byte[] ss = um1SecretFunc(sKey, rKey);
                        byte[] validationOut = validator(ss);
                        if (validationOut.SequenceEqualConstantTime(verifiedOutput)) {
                            preKey = ss;
                            state.Stop();
                        }
                    }
                });
            } else {
                Parallel.ForEach(viableReceiverKeys, (rKey, state) => {
                    foreach (EcKeyConfiguration sKey in viableSenderKeys) {
                        byte[] ss = um1SecretFunc(sKey, rKey);
                        byte[] validationOut = validator(ss);
                        if (validationOut.SequenceEqualConstantTime(verifiedOutput)) {
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
        ///     Determines which (if any) key is valid from a set of potential keys.
        ///     Where appropriate, computes confirmations in parallel.
        /// </summary>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="verifiedOutput">Known/verified output of the function if correct key is input.</param>
        /// <param name="potentialKeys">Set of potential keys.</param>
        /// <exception cref="ArgumentNullException">Key confirmation configuration or verified output is null.</exception>
        /// <exception cref="ConfigurationInvalidException">
        ///     Some aspect of configuration invalid - detailed inside exception message.
        /// </exception>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
        public static byte[] ConfirmSymmetricKey(AuthenticationFunctionConfiguration keyConfirmation,
            byte[] verifiedOutput,
            IEnumerable<byte[]> potentialKeys)
        {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
            }
            if (potentialKeys == null) {
                throw new ArgumentNullException("potentialKeys", "No potential keys supplied.");
            }
            Func<byte[], byte[]> validator = GetValidator(keyConfirmation, TagConstantBytes,
                keyConfirmation.SerialiseDto(), verifiedOutput.Length);
            byte[] preKey = null;

            Parallel.ForEach(potentialKeys, (key, state) => {
                byte[] validationOut = validator(key);
                if (validationOut.SequenceEqualConstantTime(verifiedOutput)) {
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
        ///     Gets a validation function that returns the output of a configured verification method.
        ///     Input: salt || tag || AD || message
        /// </summary>
        /// <returns>Callable validation function.</returns>
        /// <param name="keyConfirmation">Key confirmation configuration defining validation method to be employed.</param>
        /// <param name="message"></param>
        /// <param name="outputSizeBytes">Expected length of output of verification function in bytes.</param>
        /// <exception cref="ConfigurationInvalidException">
        ///     Some aspect of configuration invalid - detailed inside exception message.
        /// </exception>
        internal static Func<byte[], byte[]> GetValidator(IAuthenticationFunctionConfiguration keyConfirmation,
            byte[] tag, byte[] message,
            int? outputSizeBytes = null)
        {
            VerificationFunctionType functionType;
            try {
                functionType = keyConfirmation.FunctionType.ToEnum<VerificationFunctionType>();
            } catch (EnumerationParsingException ex) {
                throw new ConfigurationInvalidException("Verification function type is unsupported/unknown.", ex);
            }

            if (functionType == VerificationFunctionType.None) {
                throw new ConfigurationInvalidException("Verification function type cannot be None.");
            }
            if (String.IsNullOrEmpty(keyConfirmation.FunctionName)) {
                throw new ConfigurationInvalidException("Verification function name cannot be null or empty.");
            }

            const string lengthIncompatibleString = "Expected length incompatible with function specified.";

            Func<byte[], byte[]> validator; // Used as an adaptor between different validation methods
            switch (functionType) {
                case VerificationFunctionType.Kdf:
                {
                    if (outputSizeBytes == null) {
                        throw new ArgumentNullException("outputSizeBytes", "Cannot be null if KDF is being used.");
                    }
                    KeyDerivationFunction kdfEnum;
                    try {
                        kdfEnum = keyConfirmation.FunctionName.ToEnum<KeyDerivationFunction>();
                    } catch (EnumerationParsingException ex) {
                        throw new ConfigurationInvalidException("Key derivation function is unsupported/unknown.", ex);
                    }

                    validator = key => {
                        int saltSize = keyConfirmation.Salt.Length +
                                       (keyConfirmation.AdditionalData != null
                                           ? keyConfirmation.AdditionalData.Length
                                           : 0) + (tag != null ? tag.Length : 0) +
                                       (message != null ? message.Length : 0);

                        int index = keyConfirmation.Salt.Length;
                        var input = new byte[saltSize];
                        keyConfirmation.Salt.CopyBytes(0, input, 0, index);
                        if (tag.IsNullOrZeroLength() == false) {
                            tag.CopyBytes(0, input, index, tag.Length);
                        }
                        if (keyConfirmation.AdditionalData.IsNullOrZeroLength() == false) {
                            keyConfirmation.AdditionalData.CopyBytes(0, input, index,
                                keyConfirmation.AdditionalData.Length);
                            index += keyConfirmation.AdditionalData.Length;
                        }
                        if (message.IsNullOrZeroLength() == false) {
                            message.CopyBytes(0, input, index, message.Length);
                        }

                        return KeyDerivationUtility.DeriveKeyWithKdf(kdfEnum, key, input,
                            outputSizeBytes.Value, keyConfirmation.FunctionConfiguration);
                    };
                    break;
                }
                case VerificationFunctionType.Mac:
                    MacFunction macFEnum;
                    try {
                        macFEnum = keyConfirmation.FunctionName.ToEnum<MacFunction>();
                    } catch (EnumerationParsingException ex) {
                        throw new ConfigurationInvalidException("MAC function is unsupported/unknown.", ex);
                    }
                    validator = key => {
                        IMac macF = AuthenticatorFactory.CreateMacPrimitive(macFEnum, key, keyConfirmation.Salt,
                            keyConfirmation.FunctionConfiguration, keyConfirmation.Nonce);

                        if (outputSizeBytes != null && outputSizeBytes != macF.MacSize) {
                            throw new ArgumentException(lengthIncompatibleString, "outputSizeBytes");
                        }

                        if (tag.IsNullOrZeroLength() == false) {
                            macF.BlockUpdate(tag, 0, tag.Length);
                        }
                        if (keyConfirmation.AdditionalData.IsNullOrZeroLength() == false) {
                            macF.BlockUpdate(keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
                        }
                        if (message.IsNullOrZeroLength() == false) {
                            macF.BlockUpdate(message, 0, message.Length);
                        }

                        var output = new byte[macF.MacSize];
                        macF.DoFinal(output, 0);
                        return output;
                    };
                    break;
                default:
                    throw new NotSupportedException("Function type not supported for key confirmation.");
            }

            return validator;
        }
    }
}
