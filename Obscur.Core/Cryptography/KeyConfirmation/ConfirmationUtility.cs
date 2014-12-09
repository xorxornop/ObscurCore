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
using Nessos.LinqOptimizer.CSharp;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.KeyDerivation;
using Obscur.Core.DTO;
using PerfCopy;

namespace Obscur.Core.Cryptography.KeyConfirmation
{
    /// <summary>
    ///     Provides convenience methods for confirming cryptographic keys.
    /// </summary>
    public static class ConfirmationUtility
    {
        internal static readonly byte[] TagConstantBytes = Encoding.UTF8.GetBytes("OBSCURCORE_KC_V1");

        /// <summary>
        ///     Generate a verified output of a function given the correct key, to be used as a key confirmation. 
        ///     Uses confirmation canary.
        /// </summary>
        /// <param name="configuration">Configuration of the verification function.</param>
        /// <param name="key">Key to generate a confirmation output verification for.</param>
        /// <returns>Output of the verification function, given the correct key.</returns>
        /// <exception cref="ArgumentException">Key is null or zero-length.</exception>
        /// <seealso cref="SymmetricKey"/>
        /// <seealso cref="ECKeypair"/>
        /// <seealso cref="IPossessConfirmationCanary"/>
        public static byte[] GenerateVerifiedOutput(AuthenticationConfiguration configuration, SymmetricKey key)
        {
            return GenerateVerifiedOutput(configuration, key.ConfirmationCanary);
        }

        /// <summary>
        ///     Generate a verified output of a function given the correct canary, to be used as a key confirmation.
        /// </summary>
        /// <param name="configuration">Configuration of the verification function.</param>
        /// <param name="canary">Confirmation canary to generate a confirmation output verification for.</param>
        /// <returns>Output of the verification function, given the correct canary.</returns>
        /// <exception cref="ArgumentException">Key is null or zero-length.</exception>
        /// <seealso cref="SymmetricKey"/>
        /// <seealso cref="ECKeypair"/>
        /// <seealso cref="IPossessConfirmationCanary"/>
        public static byte[] GenerateVerifiedOutput(AuthenticationConfiguration configuration, byte[] canary)
        {
            if (canary.IsNullOrZeroLength()) {
                throw new ArgumentException("Canary is null or zero-length.", "canary");
            }

            Func<byte[], byte[]> validator = GetValidator(configuration, TagConstantBytes,
                configuration.SerialiseDto());
            byte[] verifiedOutput = validator(canary);

            Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "GenerateVerifiedOutput",
                "Verified output",
                verifiedOutput.ToHexString()));

            return verifiedOutput;
        }

        /// <summary>
        ///     Generate a verified output of a function given the correct key, to be used as a key confirmation. 
        ///     Uses confirmation canary.
        /// </summary>
        /// <param name="configuration">Configuration of the verification function.</param>
        /// <param name="senderKeypair">Sender keypair to generate a confirmation output verification for.</param>
        /// <param name="recipientKey">Recipient key to generate a confirmation output verification for.</param>
        /// <returns>Output of the verification function, given the correct key.</returns>
        /// <exception cref="ArgumentException">Key is null or zero-length.</exception>
        /// <seealso cref="SymmetricKey"/>
        /// <seealso cref="ECKeypair"/>
        /// <seealso cref="IPossessConfirmationCanary"/>
        public static byte[] GenerateVerifiedOutput(AuthenticationConfiguration configuration, ECKeypair senderKeypair, ECKey recipientKey) {
            Func<byte[], byte[]> validator = GetValidator(configuration, TagConstantBytes,
                configuration.SerialiseDto());

            byte[] canary = XorCanaryBytes(senderKeypair.ConfirmationCanary, recipientKey.ConfirmationCanary);
            byte[] verifiedOutput = validator(canary);

            Debug.Print(DebugUtility.CreateReportString("ConfirmationUtility", "GenerateVerifiedOutput",
                "Verified output",
                verifiedOutput.ToHexString()));

            return verifiedOutput;
        }

        /// <summary>
        ///     Determines which (if any) key is valid from a set of potential keys. 
        /// </summary>
        /// <remarks>
        ///     Where appropriate, computes confirmations in parallel.
        /// </remarks>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="verifiedOutput">Known/verified output of the function if correct key is input.</param>
        /// <param name="potentialKeys">Set of potential keys used by the sender.</param>
        /// <exception cref="ArgumentNullException">Key confirmation configuration, verified output, or potential keys is null.</exception>
        /// <exception cref="ConfigurationInvalidException">
        ///     Some aspect of configuration invalid - detailed inside exception message.
        /// </exception>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
        public static SymmetricKey ConfirmKeyFromCanary(AuthenticationConfiguration keyConfirmation,
            byte[] verifiedOutput, IEnumerable<SymmetricKey> potentialKeys)
        {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
            }
            if (potentialKeys == null) {
                throw new ArgumentNullException("potentialKeys", "No potential keys supplied.");
            }

            Func<byte[], byte[]> validator = GetValidator(keyConfirmation, TagConstantBytes,
                keyConfirmation.SerialiseDto(), verifiedOutput.Length);

            SymmetricKey preKey = null;
            Parallel.ForEach(potentialKeys, (key, state) =>
            {
                byte[] validationOut = validator(key.ConfirmationCanary);
                if (validationOut.SequenceEqualConstantTime(verifiedOutput)) {
                    preKey = key;
                    // Terminate all other validation function instances - we have found the key
                    state.Stop();
                }
            });

            return preKey;
        }

        /// <summary>
        ///     Determines which (if any) key is valid from a set of potential keys. 
        /// </summary>
        /// <remarks>
        ///     Where appropriate, computes confirmations in parallel.
        /// </remarks>
        /// <param name="keyConfirmation">Key confirmation configuration.</param>
        /// <param name="verifiedOutput">Known/verified output of the function if correct key is input.</param>
        /// <param name="potentialSenderKeys">Set of potential public keys used by the sender.</param>
        /// <param name="ephemeralKey"></param>
        /// <param name="potentialRecipientKeys">Keys used by the recipient that the sender may have used.</param>
        /// <param name="senderKey">Output of the public key associated with the private key used by the sender.</param>
        /// <param name="recipientKeypair">Output of the keypair that contains the public key used by the sender.</param>
        /// <exception cref="ArgumentNullException">Some input argument is null.</exception>
        /// <exception cref="ConfigurationInvalidException">
        ///     Some aspect of configuration invalid - detailed inside exception message.
        /// </exception>
        /// <returns>Valid key, or null if none are validated as being correct.</returns>
        public static void ConfirmKeyFromCanary(AuthenticationConfiguration keyConfirmation,
            byte[] verifiedOutput, IEnumerable<ECKey> potentialSenderKeys, ECKey ephemeralKey,
            IEnumerable<ECKeypair> potentialRecipientKeys, out ECKey senderKey, out ECKeypair recipientKeypair)
        {
            if (keyConfirmation == null) {
                throw new ArgumentNullException("keyConfirmation", "No configuration supplied.");
            }
            if (ephemeralKey == null) {
                throw new ArgumentNullException("ephemeralKey", "No ephemeral key supplied.");
            }
            if (potentialSenderKeys == null) {
                throw new ArgumentNullException("potentialSenderKeys", "No potential sender keys supplied.");
            }
            if (ephemeralKey == null) {
                throw new ArgumentNullException("ephemeralKey", "No ephemeral key supplied.");
            }
            if (potentialRecipientKeys == null) {
                throw new ArgumentNullException("potentialRecipientKeys", "No potential recipient keys supplied.");
            }

            // We can determine which, if any, of the provided keys are capable of decrypting the manifest
            var viableSenderKeys = potentialSenderKeys.AsQueryExpr().Where(key => 
                key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) && 
                key.CurveName.Equals(ephemeralKey.CurveName)).Run().ToArray();
            if (viableSenderKeys.Length == 0) {
                throw new ArgumentException(
                    "No viable sender keys found - curve provider and/or curve name do not match ephemeral key.",
                    "potentialSenderKeys");
            }

            var viableRecipientKeypairs = potentialRecipientKeys.AsQueryExpr().Where(key =>
                key.CurveProviderName.Equals(ephemeralKey.CurveProviderName) &&
                key.CurveName.Equals(ephemeralKey.CurveName)).Run().ToArray();
            if (viableRecipientKeypairs.Length == 0) {
                throw new ArgumentException(
                    "No viable recipient keys found - curve provider and/or curve name do not match ephemeral key.",
                    "potentialRecipientKeys");
            }

            Func<byte[], byte[]> validator = GetValidator(keyConfirmation, TagConstantBytes,
                keyConfirmation.SerialiseDto(), verifiedOutput.Length);

            // Temporary variables to store output in (can't access 'out' parameters inside anonymous method body)
            ECKey oSK = null;
            ECKeypair oRKP = null;
            // See which mode (by-sender / by-recipient) is better to run in parallel
            if (viableRecipientKeypairs.Length > viableSenderKeys.Length) {
                Parallel.ForEach(viableRecipientKeypairs, (rKeypair, state) => {
                    foreach (ECKey sKey in viableSenderKeys) {
                        byte[] canary = XorCanaryBytes(sKey.ConfirmationCanary, rKeypair.ConfirmationCanary);
                        byte[] validationOut = validator(canary);
                        if (validationOut.SequenceEqualConstantTime(verifiedOutput)) {
                            oSK = sKey;
                            oRKP = rKeypair;
                            state.Stop();
                        }
                    }
                });
            } else {
                Parallel.ForEach(viableSenderKeys, (sKey, state) => {
                    foreach (var rKeypair in viableRecipientKeypairs) {
                        byte[] canary = XorCanaryBytes(sKey.ConfirmationCanary, rKeypair.ConfirmationCanary);
                        byte[] validationOut = validator(canary);
                        if (validationOut.SequenceEqualConstantTime(verifiedOutput)) {
                            oSK = sKey;
                            oRKP = rKeypair;
                            state.Stop();
                        }
                    }
                });
            }

            // Assign the outputs to the 'out' parameters
            senderKey = oSK;
            recipientKeypair = oRKP;
        }

        internal static byte[] XorCanaryBytes(byte[] c0, byte[] c1) {
            int c0Length = c0.Length, c1Length = c1.Length;
            int combinedLength = Math.Max(c0.Length, c1.Length);
            byte[] combined = new byte[combinedLength];
            if (c0Length > combinedLength) {
                c0.DeepCopy_NoChecks(combinedLength, combined, combinedLength, combinedLength - c0Length);
            } else if (c1Length > combinedLength) {
                c1.DeepCopy_NoChecks(combinedLength, combined, combinedLength, combinedLength - c1Length);
            }
            c0.XorInternal(0, c1, 0, combined, 0, Math.Min(c0Length, c1Length));
            return combined;
        }

        /// <summary>
        ///     Gets a validation function that returns the output of a configured verification method.
        ///     Input: <c>tag || salt || AD || message</c>
        /// </summary>
        /// <returns>Callable validation function.</returns>
        /// <param name="keyConfirmation">Key confirmation configuration defining validation method to be employed.</param>
        /// <param name="tag"></param>
        /// <param name="message"></param>
        /// <param name="outputSizeBytes">Expected length of output of verification function in bytes.</param>
        /// <exception cref="ConfigurationInvalidException">
        ///     Some aspect of configuration invalid - detailed inside exception message.
        /// </exception>
        internal static Func<byte[], byte[]> GetValidator(IAuthenticationConfiguration keyConfirmation,
            byte[] tag, byte[] message, int? outputSizeBytes = null)
        {
            AuthenticationFunctionType functionType = keyConfirmation.FunctionType;

            if (functionType == AuthenticationFunctionType.None) {
                throw new ConfigurationInvalidException("Authentication function type cannot be None.");
            }
            if (String.IsNullOrEmpty(keyConfirmation.FunctionName)) {
                throw new ConfigurationInvalidException("Authentication function name cannot be null or empty.");
            }

            const string lengthIncompatibleString = "Expected length incompatible with function specified.";

            Func<byte[], byte[]> validator; // Used as an adaptor between different validation methods
            switch (functionType) {
                case AuthenticationFunctionType.Kdf:
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

                    validator = key => 
                    {
                        int superSaltSize = keyConfirmation.Salt.Length + 
                            (keyConfirmation.AdditionalData != null ? keyConfirmation.AdditionalData.Length : 0) + 
                            (tag != null ? tag.Length : 0) + 
                            (message != null ? message.Length : 0);
                        
                        var superSalt = new byte[superSaltSize];
                        tag.DeepCopy_NoChecks(0, superSalt, 0, tag.Length);
                        int index = tag.Length;

                        // Compose the rest of the input to the KDF (as a super-salt)
                        if (keyConfirmation.Salt.IsNullOrZeroLength() == false) {
                            keyConfirmation.Salt.DeepCopy_NoChecks(0, superSalt, index, keyConfirmation.Salt.Length);
                            index += keyConfirmation.Salt.Length;
                        }
                        if (keyConfirmation.AdditionalData.IsNullOrZeroLength() == false) {
                            keyConfirmation.AdditionalData.DeepCopy_NoChecks(0, superSalt, index,
                                keyConfirmation.AdditionalData.Length);
                            index += keyConfirmation.AdditionalData.Length;
                        }
                        if (message.IsNullOrZeroLength() == false) {
                            message.DeepCopy_NoChecks(0, superSalt, index, message.Length);
                        }

                        return KdfFactory.DeriveKeyWithKdf(kdfEnum, key, superSalt,
                            outputSizeBytes.Value, keyConfirmation.FunctionConfiguration);
                    };
                    break;
                }
                case AuthenticationFunctionType.Mac:
                    MacFunction macFEnum;
                    try {
                        macFEnum = keyConfirmation.FunctionName.ToEnum<MacFunction>();
                    } catch (EnumerationParsingException ex) {
                        throw new ConfigurationInvalidException("MAC function is unsupported/unknown.", ex);
                    }
                    validator = key => {
                        IMac macF = AuthenticatorFactory.CreateMacPrimitive(macFEnum, key, tag,
                            keyConfirmation.FunctionConfiguration, keyConfirmation.Nonce);

                        if (outputSizeBytes != null && outputSizeBytes != macF.OutputSize) {
                            throw new ArgumentException(lengthIncompatibleString, "outputSizeBytes");
                        }

                        if (keyConfirmation.Salt.IsNullOrZeroLength() == false) {
                            macF.BlockUpdate(keyConfirmation.Salt, 0, keyConfirmation.Salt.Length);
                        }
                        if (keyConfirmation.AdditionalData.IsNullOrZeroLength() == false) {
                            macF.BlockUpdate(keyConfirmation.AdditionalData, 0, keyConfirmation.AdditionalData.Length);
                        }
                        if (message.IsNullOrZeroLength() == false) {
                            macF.BlockUpdate(message, 0, message.Length);
                        }

                        var output = new byte[macF.OutputSize];
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
