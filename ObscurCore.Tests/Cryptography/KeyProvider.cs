#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System.Collections.Generic;
using System.Linq;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Cryptography.KeyAgreement;

namespace ObscurCore.Tests.Cryptography
{
    public static class KeyProviders
    {
        public static KeyProvider Alice;
        public static KeyProvider Bob;

        static KeyProviders()
        {
            Alice = new KeyProvider();
            Bob = new KeyProvider(Alice);
            // Assign each other's public keys as foreign key sources
            Alice.ForeignEcKeys = Bob.EcKeypairs.Select(keypair => keypair.ExportPublicKey());
            Bob.ForeignEcKeys = Alice.EcKeypairs.Select(keypair => keypair.ExportPublicKey());
        }
    }

    /// <summary>
    ///     Implementation of key provider for tests. Generates random keys.
    /// </summary>
    public class KeyProvider : IKeyProvider
    {
        public KeyProvider(int keysToMake = 5)
        {
            var symKeys = new List<SymmetricKey>();
            var ecKeypairs = new List<ECKeypair>();

            for (int i = 0; i < keysToMake; i++) {
                // Symmetric key
                var newSymKey = new byte[128.BitsToBytes()];
                var newSymCanary = new byte[128.BitsToBytes()];
                StratCom.EntropySupplier.NextBytes(newSymKey);
                StratCom.EntropySupplier.NextBytes(newSymCanary);
                symKeys.Add(new SymmetricKey {
                    Key = newSymKey,
                    ConfirmationCanary = newSymCanary,
                    UsePermissions = SymmetricKeyUsePermission.Encryption | SymmetricKeyUsePermission.Authentication,
                    ContextPermissions = KeyUseContextPermission.ManifestHeader | KeyUseContextPermission.PayloadItem
                });
                // EC key
                int curveIndex = StratCom.EntropySupplier.Next(Athena.Cryptography.EllipticCurves.Count);
                string curveName = Athena.Cryptography.EllipticCurves.Keys.ElementAt(curveIndex);
                ECKeypair newEcKey = KeypairFactory.GenerateECKeypair(curveName);
                ecKeypairs.Add(newEcKey);
            }

            SymmetricKeys = symKeys;
            EcKeypairs = ecKeypairs;
        }

        /// <summary>
        ///     Create a key provider with keys based off an existing key provider,
        ///     aimed at a sender-recipient relationship.
        /// </summary>
        /// <param name="other">Existing key provider to use as a basis for interoperability.</param>
        public KeyProvider(KeyProvider other)
        {
            SymmetricKeys = other.SymmetricKeys.Reverse().ToList();
            EcKeypairs = other.EcKeypairs.Select(
                item => {
                    ECKeypair newEcKeypair = KeypairFactory.GenerateECKeypair(item.CurveName);
                    var newEcCanary = new byte[128.BitsToBytes()];
                    StratCom.EntropySupplier.NextBytes(newEcCanary);
                    newEcKeypair.ConfirmationCanary = newEcCanary;
                    return newEcKeypair;
                }).ToList();
        }

        #region IKeyProvider Members

        /// <summary>
        ///     Symmetric key(s) that the local user owns.
        /// </summary>
        public IEnumerable<SymmetricKey> SymmetricKeys { get; set; }

        /// <summary>
        ///     Elliptic curve key(s) that the local user owns.
        /// </summary>
        public IEnumerable<ECKeypair> EcKeypairs { get; set; }

        /// <summary>
        ///     Elliptic curve public key(s) of foreign entities.
        /// </summary>
        public IEnumerable<ECKey> ForeignEcKeys { get; set; }

        #endregion
    }
}
