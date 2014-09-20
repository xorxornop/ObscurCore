//
//  Copyright 2014  Matthew Ducker
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
using System.Diagnostics;
using System.Text;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Custom.SEC;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Multiplier;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{
    /// <summary>
    ///     Implementation of Password Authenticated Key Exchange by Juggling (J-PAKE)
    ///     passphrase-authenticated key agreement protocol with elliptic curve math.
    /// </summary>
    public sealed class ECJpakeSession : IDisposable
    {
        #region Fields

        /// <summary>
        ///     Speciality EC base point multiplier.
        /// </summary>
        private static readonly ECMultiplier BasePointMultiplier = new FixedPointCombMultiplier();

        private static readonly byte[] MacKeyConstantBytes = Encoding.UTF8.GetBytes("JPAKE_KC");
        private static readonly byte[] MacTagConstantBytes = Encoding.UTF8.GetBytes("KC_1_U");

        /// <summary>
        ///     Provides hashing capability.
        ///     Together with field size of elliptic curve, sets security level.
        /// </summary>
        private IHash _digest;

        /// <summary>
        ///     Domain parameters for elliptic curve system.
        /// </summary>
        private readonly ECDomainParameters _domain;

        private readonly BigInteger _q;
        private ECPoint _b = null;

        // Constants

        private ECPoint _gx1;
        private ECPoint _gx2;
        private ECPoint _gx3;
        private ECPoint _gx4;

        private BigInteger _keyingMaterial;
        private BigInteger _macTag;

        /// <summary>
        ///     Shared secret.
        ///     This only contains the secret between construction and a call to CalculateKeyingMaterial().
        /// </summary>
        private byte[] _passwordBytes;

        // Variables holding private state
        private BigInteger _x2; // Private key - x1 is not stored, as it is only ephemeral

        #endregion

        /// <summary>
        ///     Start a new or resume a previous J-PAKE key agreement session.
        ///     If resuming, call RestoreState() method immediately after construction.
        /// </summary>
        /// <param name="participantId">Participant identifier.</param>
        /// <param name="passphrase">Passphrase believed to be known to both parties.</param>
        /// <param name="group">Elliptic curve group/domain (must be over F(<sub>p</sub>).</param>
        /// <param name="digest">Digest/hash function.</param>
        /// <param name="random">Random data generator/source.</param>
        public ECJpakeSession(string participantId, string passphrase, ECDomainParameters group, IHash digest,
            CsRng random)
        {
            if (String.IsNullOrEmpty(participantId)) {
                throw new ArgumentException("Participant ID must not be null/empty.");
            }
            if (String.IsNullOrEmpty(passphrase)) {
                throw new ArgumentException("Password must not be null/empty.");
            }

            if (group == null) {
                throw new ArgumentNullException("group");
            }
            if (digest == null) {
                throw new ArgumentNullException("digest");
            }
            if (random == null) {
                throw new ArgumentNullException("random");
            }

            ECCurve curve = group.Curve;
            var curveAsFp = group.Curve as FpCurve;
            if (curveAsFp == null) {
                if (curve is SecP192K1Curve) {
                    _q = ((SecP192K1Curve) curve).Q;
                } else if (curve is SecP192R1Curve) {
                    _q = ((SecP192R1Curve) curve).Q;
                } else if (curve is SecP224K1Curve) {
                    _q = ((SecP224K1Curve) curve).Q;
                } else if (curve is SecP224R1Curve) {
                    _q = ((SecP224R1Curve) curve).Q;
                } else if (curve is SecP256K1Curve) {
                    _q = ((SecP256K1Curve) curve).Q;
                } else if (curve is SecP256R1Curve) {
                    _q = ((SecP256R1Curve) curve).Q;
                } else if (curve is SecP384R1Curve) {
                    _q = ((SecP384R1Curve) curve).Q;
                } else if (curve is SecP521R1Curve) {
                    _q = ((SecP521R1Curve) curve).Q;
                } else {
                    throw new ArgumentException("Curve in EC domain parameters must be over F(p)", "group");
                }
            } else {
                _q = curveAsFp.Q;
            }

            ParticipantId = participantId;
            _passwordBytes = Encoding.UTF8.GetBytes(passphrase);
            _domain = group;
            _digest = digest;
            EntropySupply = random;

            ProtocolState = State.Initialised;
        }

        #region Properties

        /// <summary>
        ///     The state of the protocol.
        /// </summary>
        public State ProtocolState { get; private set; }

        /// <summary>
        ///     Unique identifier of this local instance's participant.
        ///     The two participants in the exchange must NOT share the same ID.
        /// </summary>
        public string ParticipantId { get; private set; }

        /// <summary>
        ///     Unique identifier of the remote instance's participant (partner).
        ///     The two participants in the exchange must NOT share the same ID.
        /// </summary>
        public string PartnerParticipantId { get; private set; }

        /// <summary>
        ///     Source of random bytes.
        /// </summary>
        public CsRng EntropySupply { get; private set; }

        #endregion

        /// <summary>
        ///     Restores the state of an incomplete J-PAKE session,
        ///     given private keys and DTO objects created/received from that session.
        /// </summary>
        /// <param name="x2">Private key.</param>
        /// <param name="round1Created">Round 1 created/sent.</param>
        /// <param name="round1Received">Round 1 received.</param>
        /// <param name="round2Created">Round 2 created/sent.</param>
        /// <param name="round2Received">Round 2 received.</param>
        /// <param name="round3Created">Round 3 created/sent.</param>
        public void RestoreState(byte[] x2, ECJpakeRound1 round1Created, ECJpakeRound1 round1Received = null,
            ECJpakeRound2 round2Created = null, ECJpakeRound2 round2Received = null, JpakeRound3 round3Created = null)
        {
            if (ProtocolState != State.Initialised) {
                throw new InvalidOperationException("Cannot restore state of already-active protocol session!");
            }

            if (round1Created == null) {
                throw new ArgumentNullException("round1Created");
            }

            _gx1 = _domain.Curve.DecodePoint(round1Created.GX1);
            _gx2 = _domain.Curve.DecodePoint(round1Created.GX2);
            ProtocolState = State.Round1Created;

            if (round1Received != null) {
                if (String.IsNullOrEmpty(round1Received.ParticipantId)) {
                    throw new ArgumentException("Partner participant ID in round 1 received is null or empty.");
                }
                PartnerParticipantId = round1Received.ParticipantId;
                _gx3 = _domain.Curve.DecodePoint(round1Received.GX1);
                _gx4 = _domain.Curve.DecodePoint(round1Received.GX2);
                ProtocolState = State.Round1Validated;
            } else {
                return;
            }

            if (round2Created != null) {
                ProtocolState = State.Round2Created;
            } else {
                return;
            }

            if (round2Received != null) {
                if (PartnerParticipantId.Equals(round2Received.ParticipantId, StringComparison.Ordinal) == false) {
                    throw new ArgumentException("Partner participant ID of round 2 does not match value from round 1.");
                }
                _b = _domain.Curve.DecodePoint(round2Received.A);
                ProtocolState = State.Round2Validated;
            } else {
                return;
            }

            if (round3Created != null) {
                // Keying material has been calculated
                _b = _domain.Curve.DecodePoint(round2Received.A);
                ProtocolState = State.Round3Created;
            } else {
                if (x2.IsNullOrZeroLength()) {
                    throw new ArgumentException("Session cannot be resumed without private key x2Export. Aborting.");
                }
            }
        }

        /// <summary>
        ///     Provides the ability to suspend the session for later resumption by exporting the
        ///     session participant's private key. This key must be stored securely!
        ///     DTO state objects created/sent and received thus far must also be retained
        ///     (these are not output by this method).
        /// </summary>
        public void SuspendSession(out byte[] x2Export)
        {
            x2Export = _x2.ToByteArray();
        }

        #region Round 1

        /// <summary>
        ///     Creates a round 1 (zero-knowledge proof) DTO to send to the partner participant.
        /// </summary>
        public ECJpakeRound1 CreateRound1ToSend()
        {
            if (ProtocolState >= State.Round1Created) {
                throw new InvalidOperationException("Round1 payload already created for " + ParticipantId);
            }

            BigInteger x1 = BigInteger.CreateRandomInRange(BigInteger.One, _domain.N.Subtract(BigInteger.One),
                EntropySupply);
            _x2 = BigInteger.CreateRandomInRange(BigInteger.One, _domain.N.Subtract(BigInteger.One), EntropySupply);
            _gx1 = BasePointMultiplier.Multiply(_domain.G, x1);
            _gx2 = BasePointMultiplier.Multiply(_domain.G, _x2);

            ECPoint V1, V2;
            BigInteger r1, r2;
            CreateZeroKnowledgeProof(_domain.G, x1, _gx1, ParticipantId, out V1, out r1);
            CreateZeroKnowledgeProof(_domain.G, _x2, _gx2, ParticipantId, out V2, out r2);

            var dto = new ECJpakeRound1 {
                ParticipantId = ParticipantId,
                GX1 = _gx1.GetEncoded(),
                X1V = V1.GetEncoded(),
                X1R = r1.ToByteArray(),
                GX2 = _gx2.GetEncoded(),
                X2V = V2.GetEncoded(),
                X2R = r2.ToByteArray()
            };

            ProtocolState = State.Round1Created;
            return dto;
        }

        /// <summary>
        ///     Validates the round 1 (zero-knowledge proof) DTO received from the partner participant.
        /// </summary>
        /// <param name="round1Received">Round 1 DTO received from partner participant.</param>
        public void ValidateRound1Received(ECJpakeRound1 round1Received)
        {
            if (ProtocolState >= State.Round1Validated) {
                throw new InvalidOperationException("Validation already attempted for round 1 payload for "
                                                    + ParticipantId);
            }
            if (String.IsNullOrEmpty(round1Received.ParticipantId)) {
                throw new ArgumentException("Partner participant ID in round 1 DTO received is null or empty.");
            }

            PartnerParticipantId = round1Received.ParticipantId;
            _gx3 = _domain.Curve.DecodePoint(round1Received.GX1);
            _gx4 = _domain.Curve.DecodePoint(round1Received.GX2);

            ECPoint X3V = _domain.Curve.DecodePoint(round1Received.X1V);
            var X3R = new BigInteger(round1Received.X1R);
            ECPoint X4V = _domain.Curve.DecodePoint(round1Received.X2V);
            var X4R = new BigInteger(round1Received.X2R);

            if (ZeroKnowledgeProofValid(_domain.G, _gx3, X3V, X3R,
                PartnerParticipantId) == false ||
                ZeroKnowledgeProofValid(_domain.G, _gx4, X4V, X4R,
                    PartnerParticipantId) == false) {
                throw new CryptoException("Verification of zero-knowledge proof in round 1 failed.");
            }

            ProtocolState = State.Round1Validated;
        }

        #endregion

        #region Round 2

        /// <summary>
        ///     Creates a round 2 (zero-knowledge proof) DTO to send to the partner participant.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///     Prior round (1) has not been completed yet, or method may have been called more than once.
        /// </exception>
        public ECJpakeRound2 CreateRound2ToSend()
        {
            if (ProtocolState >= State.Round2Created) {
                throw new InvalidOperationException("Round 2 payload already created for " + ParticipantId);
            }
            if (ProtocolState < State.Round1Validated) {
                throw new InvalidOperationException("Round 1 payload must be validated prior to creating Round 2 payload for "
                                                    + ParticipantId);
            }

            var s1 = new BigInteger(_passwordBytes);

            ECPoint GA = _gx1.Add(_gx3).Add(_gx4);
            BigInteger x2s1 = _x2.Multiply(s1).Mod(_domain.N);
            ECPoint A = BasePointMultiplier.Multiply(GA, x2s1);

            ECPoint X2sV;
            BigInteger X2sR;
            CreateZeroKnowledgeProof(GA, x2s1, A, ParticipantId, out X2sV, out X2sR);

            var dto = new ECJpakeRound2 {
                ParticipantId = ParticipantId,
                A = A.GetEncoded(),
                X2sV = X2sV.GetEncoded(),
                X2sR = X2sR.ToByteArray()
            };

            ProtocolState = State.Round2Created;
            return dto;
        }

        /// <summary>
        ///     Validates the round 2 (zero-knowledge proof) DTO received from the partner participant.
        /// </summary>
        /// <param name="round2Received">Round 2 DTO received form partner participant.</param>
        /// <exception cref="InvalidOperationException">
        ///     Prior round (1) has not been completed yet, or method may have been called more than once.
        /// </exception>
        /// <exception cref="CryptoException">
        ///     Verification of zero-knowledge proof failed. Possible attempted impersonation / MiTM.
        /// </exception>
        public void ValidateRound2Received(ECJpakeRound2 round2Received)
        {
            if (ProtocolState >= State.Round2Validated) {
                throw new InvalidOperationException("Validation already attempted for round 2 payload for " +
                                                    ParticipantId);
            }
            if (ProtocolState < State.Round1Validated) {
                throw new InvalidOperationException("Round 1 payload must be validated prior to validating round 2 payload for "
                                                    + ParticipantId);
            }
            if (String.IsNullOrEmpty(round2Received.ParticipantId)) {
                throw new ArgumentException("Partner participant ID in round 2 received is null or empty.");
            }
            if (PartnerParticipantId.Equals(round2Received.ParticipantId, StringComparison.Ordinal) == false) {
                throw new CryptoException("Partner participant ID of round 2 DTO does not match value from round 1.");
            }

            ECPoint X4sV = _domain.Curve.DecodePoint(round2Received.X2sV);
            var X4sR = new BigInteger(round2Received.X2sR);

            _b = _domain.Curve.DecodePoint(round2Received.A);
            // Calculate GB : GX1 + GX3 + GX4 symmetrically
            ECPoint GB = _gx3.Add(_gx1).Add(_gx2);

            if (ZeroKnowledgeProofValid(GB, _b, X4sV, X4sR, PartnerParticipantId) == false) {
                throw new CryptoException("Round 2 validation failed. Possible impersonation attempt.");
            }

            ProtocolState = State.Round2Validated;
        }

        #endregion

        #region Round 3

        /// <summary>
        ///     Creates a round 3 (key confirmation) DTO to send to the partner participant.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///     Prior rounds (1 and 2) have not been completed yet, or method may have been called more than once.
        /// </exception>
        public JpakeRound3 CreateRound3ToSend()
        {
            if (ProtocolState >= State.Round3Created) {
                throw new InvalidOperationException("Round 3 already created for " + ParticipantId);
            }

            _keyingMaterial = CalculateKeyingMaterialInternal();
            _macTag = CalculateMacTag(ParticipantId, PartnerParticipantId, _gx1, _gx2, _gx3, _gx4,
                _keyingMaterial);

            var dto = new JpakeRound3 {
                ParticipantId = ParticipantId,
                VerifiedOutput = _macTag.ToByteArrayUnsigned()
            };

            ProtocolState = State.Round3Created;

            return dto;
        }

        /// <summary>
        ///     Validates the round 3 (key confirmation) DTO received from the partner participant.
        /// </summary>
        /// <param name="round3Received">Round 3 DTO received from partner participant.</param>
        /// <param name="keyingMaterial">Shared secret to be derived further before use as a key (e.g. by a KDF).</param>
        /// <exception cref="InvalidOperationException">
        ///     Key calculation and/or prior rounds (1 and 2) have not been completed yet, or
        ///     method may have been called more than once.
        /// </exception>
        /// <exception cref="CryptoException">
        ///     Key confirmation failed - partner participant derived a different key. The passphrase used differs.
        ///     Possible attempted impersonation / MiTM.
        /// </exception>
        public void ValidateRound3Received(JpakeRound3 round3Received, out byte[] keyingMaterial)
        {
            if (ProtocolState == State.Round3Validated) {
                throw new InvalidOperationException("Validation already attempted for round 3 for " + ParticipantId);
            }
            if (ProtocolState < State.KeyCalculated) {
                throw new InvalidOperationException(
                    "Keying material must be calculated validated prior to validating round 3 for " + ParticipantId);
            }

            if (String.IsNullOrEmpty(round3Received.ParticipantId)) {
                throw new ArgumentException("Partner participant ID in round 3 DTO received is null or empty.");
            }
            if (PartnerParticipantId.Equals(round3Received.ParticipantId, StringComparison.Ordinal) == false) {
                throw new CryptoException("Partner participant ID of round 3 does not match value from rounds 1 & 2.");
            }

            var receivedTag = new BigInteger(round3Received.VerifiedOutput);

            if (_keyingMaterial == null) {
                CalculateKeyingMaterialInternal();
            }

            BigInteger expectedTag = CalculateMacTag(PartnerParticipantId, ParticipantId,
                _gx3, _gx4, _gx1, _gx2, _keyingMaterial);

            byte[] expectedMacTagBytes = expectedTag.ToByteArrayUnsigned();
            byte[] receivedMacTagBytes = receivedTag.ToByteArrayUnsigned();

            if (expectedMacTagBytes.SequenceEqualConstantTime(receivedMacTagBytes) == false) {
                throw new CryptoException("Key confirmation failed - partner MAC tag failed to match expected value.");
            }

            // Return the confirmed key to the participant
            keyingMaterial = _keyingMaterial.ToByteArrayUnsigned();

            // Clear sensitive state
            _keyingMaterial = null;
            _passwordBytes = null;
            _macTag = null;
            _x2 = null;
            _gx1 = null;
            _gx2 = null;
            _gx3 = null;
            _gx4 = null;

            ProtocolState = State.Round3Validated;
        }

        #endregion

        /// <summary>
        ///     Calculates the derived shared secret - this can be used externally, skipping key confirmation (NOT RECOMMENDED).
        ///     A session key must be derived from this key material using a secure key derivation function (KDF).
        ///     The KDF used to derive the key is handled externally.
        /// </summary>
        internal byte[] CalculateKeyingMaterial()
        {
            return CalculateKeyingMaterialInternal().ToByteArrayUnsigned();
        }

        /// <summary>
        ///     Calculates keying material derived from shared secrets and passphrase.
        /// </summary>
        private BigInteger CalculateKeyingMaterialInternal()
        {
            if (ProtocolState >= State.KeyCalculated) {
                throw new InvalidOperationException("Key already calculated for " + ParticipantId);
            }
            if (ProtocolState < State.Round2Validated) {
                throw new InvalidOperationException("Round 2 must be validated prior to creating key for " +
                                                    ParticipantId);
            }

            var s1 = new BigInteger(_passwordBytes);

            // Clear secret
            _passwordBytes.SecureWipe();
            _passwordBytes = null;

            // Prepare BigInteger to be hashed
            ECPoint GX4x2s1 = BasePointMultiplier.Multiply(_gx4, _x2.Multiply(s1).Mod(_domain.N));
            ECPoint normalised = BasePointMultiplier.Multiply(_b.Subtract(GX4x2s1), _x2).Normalize();

            BigInteger preKey = normalised.AffineXCoord.ToBigInteger();

            // Clear private keys from memory
            _x2 = null;
            _b = null;
            // Do not clear GX1-4, as these are needed for key confirmation (round 3)

            ProtocolState = State.KeyCalculated;

            return Hash(preKey);
        }

        /// <summary>
        ///     Creates a zero knowledge proof.
        /// </summary>
        private void CreateZeroKnowledgeProof(ECPoint generator, BigInteger x, ECPoint X,
            string participantId, out ECPoint V, out BigInteger r)
        {
            // Generate a random v from [1, n-1], and compute V = G*v
            BigInteger v = BigInteger.CreateRandomInRange(BigInteger.One,
                _domain.N.Subtract(BigInteger.One), EntropySupply);

            V = BasePointMultiplier.Multiply(generator, v); // g * V

            BigInteger h = Hash(generator, V, X, participantId);
            r = v.Subtract(x.Multiply(h)).Mod(_domain.N); // v - (x * h) mod n
        }

        /// <summary>
        ///     Verifies a zero knowledge proof.
        /// </summary>
        /// <returns><c>true</c>, if zero knowledge proof is valid/correct, <c>false</c> otherwise.</returns>
        private bool ZeroKnowledgeProofValid(ECPoint generator, ECPoint X, ECPoint V, BigInteger r,
            string participantId)
        {
            // ZKP: { V=G*v, r }

            BigInteger h = Hash(generator, V, X, participantId);

            // Public key validation based on p. 25
            // http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf

            // 1. X != infinity
            if (X.IsInfinity) {
                return false;
            }

            BigInteger xCoord = X.AffineXCoord.ToBigInteger();
            BigInteger yCoord = X.AffineYCoord.ToBigInteger();
            BigInteger qSub1 = _q.Subtract(BigInteger.One);

            // 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
            if (xCoord.CompareTo(BigInteger.Zero) == -1 || xCoord.CompareTo(qSub1) == 1 ||
                yCoord.CompareTo(BigInteger.Zero) == -1 || yCoord.CompareTo(qSub1) == 1) 
            {
                Debug.WriteLine("Point X coordinates not in Fq.");
                return false;
            }

            // 3. Check X lies on the curve
            try {
                if (X.IsValid() == false) {
                    Debug.WriteLine("Point X not valid.");
                    return false;
                }
            } catch (Exception e) {
                Debug.WriteLine("Check that point X is on curve failed.\n" + e.StackTrace);
                return false;
            }

            // 4. Check that nX = infinity.
            // It is equivalent - but more more efficient - to check the cofactor*X is not infinity.
            if (X.Multiply(_domain.Curve.Cofactor).IsInfinity) {
                Debug.WriteLine("X mult H (cofactor) == infinity");
                return false;
            }

            // Now check if V = G*r + X*h. 
            // Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
            ECPoint Gr = BasePointMultiplier.Multiply(generator, r);
            ECPoint Xh = BasePointMultiplier.Multiply(X, h.Mod(_domain.Curve.Order));

            if (V.Equals(Gr.Add(Xh)) == false) {
                return false;
            }

            // ZKP is valid
            return true;
        }

        /// <summary>
        ///     Hashes a BigInteger into another BigInteger.
        /// </summary>
        private BigInteger Hash(BigInteger k)
        {
            _digest.Reset();

            // Item is prefixed with its length as a little-endian 4-byte unsigned integer
            byte[] kBytes = k.ToByteArray();
            var lengthPrefix = new byte[4];
            Pack.UInt32_To_LE((uint) kBytes.Length, lengthPrefix);
            _digest.BlockUpdate(lengthPrefix, 0, 4);
            _digest.BlockUpdate(kBytes, 0, kBytes.Length);

            var hash = new byte[_digest.DigestSize];
            _digest.DoFinal(hash, 0);

            return new BigInteger(1, hash);
        }

        /// <summary>
        ///     Calculates the hash for a zero-knowledge proof.
        /// </summary>
        private BigInteger Hash(ECPoint generator, ECPoint V, ECPoint X, string participantId)
        {
            _digest.Reset();

            // Each item is prefixed with its length as a little-endian 4-byte unsigned integer
            var lengthPrefix = new byte[4];

            byte[] generatorBytes = generator.GetEncoded();
            Pack.UInt32_To_LE((uint) generatorBytes.Length, lengthPrefix);
            _digest.BlockUpdate(lengthPrefix, 0, 4);
            _digest.BlockUpdate(generatorBytes, 0, generatorBytes.Length);

            byte[] vBytes = V.GetEncoded();
            Pack.UInt32_To_LE((uint) vBytes.Length, lengthPrefix);
            _digest.BlockUpdate(lengthPrefix, 0, 4);
            _digest.BlockUpdate(vBytes, 0, vBytes.Length);

            byte[] xBytes = X.GetEncoded();
            Pack.UInt32_To_LE((uint) xBytes.Length, lengthPrefix);
            _digest.BlockUpdate(lengthPrefix, 0, 4);
            _digest.BlockUpdate(xBytes, 0, xBytes.Length);

            byte[] idBytes = Encoding.UTF8.GetBytes(participantId);
            Pack.UInt32_To_LE((uint) idBytes.Length, lengthPrefix);
            _digest.BlockUpdate(lengthPrefix, 0, 4);
            _digest.BlockUpdate(idBytes, 0, idBytes.Length);

            var hash = new byte[_digest.DigestSize];
            _digest.DoFinal(hash, 0);

            return new BigInteger(hash);
        }

        /// <summary>
        ///     Calculates the MacTag for a key confirmation.
        /// </summary>
        /// <remarks>
        ///     Calculates the MacTag (to be used for key confirmation), as defined by 
        ///     NIST SP 800-56A Revision 1, Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes 
        ///     (http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf)
        ///     <para>MacTag = HMAC(MacKey, MacLen, MacData)</para>
        ///     <para>MacKey = H(K || "JPAKE_KC")</para>
        ///     <para>MacData = "KC_1_U" || participantId || partnerParticipantId || gx1 || gx2 || gx3 || gx4</para>
        ///     <para>
        ///         Note that both participants use "KC_1_U" because the sender of the round 3 message is always 
        ///         the initiator for key confirmation. 
        ///         Participant identifiers and GX numbers are swapped symmetrically to calculate partner's value when 
        ///         performing verification in key confirmation.
        ///     </para>
        /// </remarks>
        /// <returns>The MagTag.</returns>
        /// <param name="participantId">Participant identifier.</param>
        /// <param name="partnerParticipantId">Partner participant identifier.</param>
        /// <param name="gx1">GX1 (GX3 for partner).</param>
        /// <param name="gx2">GX2 (GX4 for partner).</param>
        /// <param name="gx3">GX3 (GX1 for partner).</param>
        /// <param name="gx4">GX4 (GX2 for partner).</param>
        /// <param name="keyingMaterial">Keying material.</param>
        private BigInteger CalculateMacTag(string participantId, string partnerParticipantId,
            ECPoint gx1, ECPoint gx2, ECPoint gx3, ECPoint gx4, BigInteger keyingMaterial)
        {
            _digest.Reset();

            byte[] keyingMaterialBytes = keyingMaterial.ToByteArrayUnsigned();
            _digest.BlockUpdate(keyingMaterialBytes, 0, keyingMaterialBytes.Length);

            // This constant is used to ensure that the mac key is NOT the same as the derived key.
            byte[] constantBytes = MacKeyConstantBytes;
            _digest.BlockUpdate(constantBytes, 0, constantBytes.Length);

            var macKey = new byte[_digest.DigestSize];
            _digest.DoFinal(macKey, 0);

            // Create and initialise HMAC primitive
            var hmac = new HMac(_digest);
            hmac.Init(macKey);

            macKey.SecureWipe();
            macKey = null;

            // MacData = "KC_1_U" || participantId || partnerParticipantId || gx1 || gx2 || gx3 || gx4.
            byte[] protocolTag = MacTagConstantBytes;
            hmac.BlockUpdate(protocolTag, 0, protocolTag.Length);

            byte[] participantTag = Encoding.UTF8.GetBytes(participantId);
            hmac.BlockUpdate(participantTag, 0, participantTag.Length);

            byte[] partnerParticipantTag = Encoding.UTF8.GetBytes(partnerParticipantId);
            hmac.BlockUpdate(partnerParticipantTag, 0, partnerParticipantTag.Length);

            byte[] gx1Bytes = gx1.GetEncoded();
            hmac.BlockUpdate(gx1Bytes, 0, gx1Bytes.Length);

            byte[] gx2Bytes = gx2.GetEncoded();
            hmac.BlockUpdate(gx2Bytes, 0, gx2Bytes.Length);

            byte[] gx3Bytes = gx3.GetEncoded();
            hmac.BlockUpdate(gx3Bytes, 0, gx3Bytes.Length);

            byte[] gx4Bytes = gx4.GetEncoded();
            hmac.BlockUpdate(gx4Bytes, 0, gx4Bytes.Length);

            var macTag = new byte[hmac.MacSize];
            hmac.DoFinal(macTag, 0);
            return new BigInteger(macTag);
        }

        /// <summary>
        ///     Possible states in the J-PAKE key agreement protocol.
        /// </summary>
        /// <remarks>
        ///     Protocol progresses through these states sequentially.
        /// </remarks>
        public enum State : byte
        {
            Noninitialised = 0x00,
            Initialised = 0x01,
            Round1Created = 0x02,
            Round1Validated = 0x04,
            Round2Created = 0x08,
            Round2Validated = 0x10,
            KeyCalculated = 0x20,
            Round3Created = 0x40,
            Round3Validated = 0x80
        }

        public void Dispose()
        {
            if (_passwordBytes != null) {
                _passwordBytes.SecureWipe();
            }
            _keyingMaterial = null;
            _macTag = null;
            _x2 = null;
            _gx1 = null;
            _gx2 = null;
            _gx3 = null;
            _gx4 = null;
        }
    }
}
