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
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Support;
using System.Diagnostics;
using ObscurCore.DTO;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Custom.SEC;
using ObscurCore.Cryptography.Support.Math.EllipticCurve.Multiplier;

namespace ObscurCore.Cryptography.KeyAgreement.Primitives
{

	public class EcJpakeParticipant
	{
		/// <summary>
		/// The state of the protocol.
		/// </summary>
		protected State ProtocolState { get; private set; }

		protected enum State : byte
		{
			Initialised 	= 0,
			Round1Created 	= 10,
			Round1Validated = 20,
			Round2Created 	= 30,
			Round2Validated = 40,
			KeyCalculated 	= 50,
			Round3Created 	= 60,
			Round3Validated = 70
		}

		/// <summary>
		/// Unique identifier of this local instance's participant.
		/// The two participants in the exchange must NOT share the same ID.
		/// </summary>
		public string ParticipantId { get; private set; }

		/// <summary>
		/// Unique identifier of the remote instance's participant (partner).
		/// The two participants in the exchange must NOT share the same ID.
		/// </summary>
		public string PartnerParticipantId { get; private set; }

		/// <summary>
		/// Source of random bytes.
		/// </summary>
		public SecureRandom Random { get; private set; }

		/// <summary>
		/// Speciality EC multiplier.
		/// </summary>
		private ECMultiplier _ecMultiplier = new FixedPointCombMultiplier();

		/// <summary>
		/// Provides hashing capability. 
		/// Together with field size of elliptic curve, sets security level.
		/// </summary>
		private readonly IDigest _digest;

		/// <summary>
		/// Domain parameters for elliptic curve system.
		/// </summary>
		private readonly ECDomainParameters _domain;

		// Convenience access variables of EC parameters
		private readonly BigInteger _q, _cofactor;

		// Variables holding private state
		private BigInteger _x1 = null, _x2 = null; // Private keys

		private ECPoint _GX1 = null, _GX2 = null, _GX3 = null, _GX4 = null;
		private ECPoint _B = null;

		/// <summary>
		/// Shared secret. 
		/// This only contains the secret between construction and a call to CalculateKeyingMaterial().
		/// </summary>
		private byte[] _secret;


		// Constants
		protected static byte[] MacKeyConstantBytes = System.Text.Encoding.UTF8.GetBytes ("JPAKE_KC");
		protected static byte[] MacTagConstantBytes = System.Text.Encoding.UTF8.GetBytes ("KC_1_U");


		public EcJpakeParticipant(string participantId, string password, ECDomainParameters group, IDigest digest, SecureRandom random) {
			ECCurve curve = group.Curve;
			var curveAsFp = group.Curve as FpCurve;
			if (curveAsFp == null) {
				if (curve is SecP192K1Curve) {
					_q = ((SecP192K1Curve)curve).Q;
				} else if (curve is SecP192R1Curve) {
					_q = ((SecP192R1Curve)curve).Q;
				} else if (curve is SecP256K1Curve) {
					_q = ((SecP256K1Curve)curve).Q;
				} else if (curve is SecP256R1Curve) {
					_q = ((SecP256R1Curve)curve).Q;
				} else if (curve is SecP521R1Curve) {
					_q = ((SecP521R1Curve)curve).Q;
				} else {
					throw new ArgumentException ("Curve in EC domain parameters must be over F(p)", "group");
				}
			} else {
				_q = curveAsFp.Q;
			}

			_domain = group;
			_cofactor = _domain.H;

//			JpakeUtility.ValidateNotNull(participantId, "participantId");
//			JpakeUtility.ValidateNotNull(password, "password");
//			JpakeUtility.ValidateNotNull(group, "p");
//			JpakeUtility.ValidateNotNull(digest, "digest");
//			JpakeUtility.ValidateNotNull(random, "random");

			if (String.IsNullOrEmpty(password)) {
				throw new ArgumentException("Password must not be empty.");
			}

			ParticipantId = participantId;
			_secret = System.Text.Encoding.UTF8.GetBytes (password);
			_digest = digest;
			Random = random;
			ProtocolState = State.Initialised;
		}


		public void RestoreState (byte[] x1, byte[] x2, JpakeRound1 round1Created, JpakeRound1 round1Received = null, 
			JpakeRound2 round2Created = null, JpakeRound2 round2Received = null) 
		{
			if (ProtocolState != State.Initialised) {
				throw new InvalidOperationException ("Cannot restore state of already-active protocol session!");
			}

			if (round1Created == null) {
				throw new ArgumentNullException ("round1Created");
			}

			_GX1 = _domain.Curve.DecodePoint (round1Created.GX1);
			_GX2 = _domain.Curve.DecodePoint (round1Created.GX2);
			ProtocolState = State.Round1Created;

			if (round1Received != null) {
				PartnerParticipantId = round1Received.ParticipantId;
				_GX3 = _domain.Curve.DecodePoint (round1Received.GX1);
				_GX4 = _domain.Curve.DecodePoint (round1Received.GX2);
				ProtocolState = State.Round1Validated;
			}

			if (round2Created != null) {
				ProtocolState = State.Round2Created;
			}

			if (round2Received != null) {
				_B = _domain.Curve.DecodePoint (round2Received.A);
				ProtocolState = State.Round2Validated;
			}
		}

		/// <summary>
		/// Creates a zero knowledge proof (Schnorr signature).
		/// </summary>
		protected void CreateZeroKnowledgeProof (ECPoint generator, BigInteger x, ECPoint X, string participantId, 
			out ECPoint V, out BigInteger r) 
		{
			// Generate a random v from [1, n-1], and compute V = G*v
			BigInteger v = BigIntegers.CreateRandomInRange(BigInteger.One, 
				_domain.N.Subtract(BigInteger.One), Random);

			V = _ecMultiplier.Multiply (generator, v); // gV

			BigInteger h = Hash (generator, V, X, participantId);
			r = v.Subtract(x.Multiply(h)).Mod(_domain.N); // v - (x * h) mod n
		}

		/// <summary>
		/// Verifies a zero knowledge proof (Schnorr signature).
		/// </summary>
		protected bool VerifyZeroKnowledgeProof (ECPoint generator, ECPoint X, ECPoint V, BigInteger r, string participantId) {
			// ZKP: {V=G*v, r}

			BigInteger h = Hash(generator, V, X, participantId);

			// Public key validation based on p. 25
			// http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf

			// 1. X != infinity
			if (X.IsInfinity)
				return false;

			BigInteger xCoord = X.AffineXCoord.ToBigInteger ();
			BigInteger yCoord = X.AffineYCoord.ToBigInteger ();
			BigInteger qSub1 = _q.Subtract(BigInteger.One);

			// 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
			if (xCoord.CompareTo(BigInteger.Zero) == -1 || xCoord.CompareTo(qSub1) == 1 ||
				yCoord.CompareTo(BigInteger.Zero) == -1 || yCoord.CompareTo(qSub1) == 1) 
			{
				Debug.WriteLine ("Point X coordinates not in Fq.");
				return false;
			}

			// 3. Check X lies on the curve
			try {
				_domain.Curve.DecodePoint(X.GetEncoded());
			} catch(Exception e) {
				Debug.WriteLine ("Check that point X is on curve failed.\n" + e.StackTrace);
				return false;
			}

			// 4. Check that nX = infinity.
			// It is equivalent - but more more efficient - to check the coFactor*X is not infinity
			if (X.Multiply (_cofactor).IsInfinity) {
				Debug.WriteLine ("X mult H (cofactor) == infinity");
				return false;
			}

			// Now check if V = G*r + X*h. 
			// Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
			ECPoint Gr = _ecMultiplier.Multiply (generator, r);
			ECPoint Xh = _ecMultiplier.Multiply (X, h.Mod (_domain.N));

			if (V.Equals(Gr.Add(Xh))) {
				return true;
			} else {
				return false;
			}
		}


		private BigInteger Hash (BigInteger k) {
			// Item is prefixed with its length as a little-endian 4-byte unsigned integer
			byte[] lengthPrefix = new byte[4];
			byte[] kBytes = k.ToByteArray ();
			Pack.UInt32_To_LE ((uint)kBytes.Length, lengthPrefix);
			_digest.BlockUpdate (lengthPrefix, 0, 4);
			_digest.BlockUpdate (kBytes, 0, kBytes.Length);

			byte[] hash = new byte[_digest.DigestSize];
			_digest.DoFinal (hash, 0);

			return new BigInteger (1, hash);
		}

		private BigInteger Hash (ECPoint generator, ECPoint V, ECPoint X, string participantId) {
			// Each item is prefixed with its length as a little-endian 4-byte unsigned integer
			byte[] lengthPrefix = new byte[4];

			byte[] generatorBytes = generator.GetEncoded ();
			Pack.UInt32_To_LE ((uint)generatorBytes.Length, lengthPrefix);
			_digest.BlockUpdate (lengthPrefix, 0, 4);
			_digest.BlockUpdate (generatorBytes, 0, generatorBytes.Length);

			byte[] VBytes = V.GetEncoded ();
			Pack.UInt32_To_LE ((uint)VBytes.Length, lengthPrefix);
			_digest.BlockUpdate (lengthPrefix, 0, 4);
			_digest.BlockUpdate (VBytes, 0, VBytes.Length);

			byte[] XBytes = X.GetEncoded ();
			Pack.UInt32_To_LE ((uint)XBytes.Length, lengthPrefix);
			_digest.BlockUpdate (lengthPrefix, 0, 4);
			_digest.BlockUpdate (XBytes, 0, XBytes.Length);

			byte[] idBytes = System.Text.Encoding.UTF8.GetBytes (participantId);
			Pack.UInt32_To_LE ((uint)idBytes.Length, lengthPrefix);
			_digest.BlockUpdate (lengthPrefix, 0, 4);
			_digest.BlockUpdate (idBytes, 0, idBytes.Length);

			byte[] hash = new byte[_digest.DigestSize];
			_digest.DoFinal (hash, 0);

			return new BigInteger (hash);
		}

		/// <summary>
		/// Creates and returns a KZP DTO to send to the other participant during round 1.
		/// </summary>
		public JpakeRound1 CreateRound1ToSend() {
			if (ProtocolState >= State.Round1Created) {
				throw new InvalidOperationException("Round1 payload already created for " + ParticipantId);
			}

			_x1 = BigIntegers.CreateRandomInRange(BigInteger.One, _domain.N.Subtract(BigInteger.One), Random);
			_x2 = BigIntegers.CreateRandomInRange(BigInteger.One, _domain.N.Subtract(BigInteger.One), Random);

			_GX1 = _ecMultiplier.Multiply(_domain.G, _x1);
			_GX2 = _ecMultiplier.Multiply(_domain.G, _x2);

			ECPoint V1, V2;
			BigInteger r1, r2;
			CreateZeroKnowledgeProof (_domain.G, _x1, _GX1, ParticipantId, out V1, out r1);
			CreateZeroKnowledgeProof (_domain.G, _x2, _GX2, ParticipantId, out V2, out r2);

			var dto = new JpakeRound1 {
				ParticipantId = ParticipantId,
				GX1 = _GX1.GetEncoded(),
				X1V = V1.GetEncoded(),
				X1R = r1.ToByteArray(),
				GX2 = _GX2.GetEncoded(),
				X2V = V2.GetEncoded(),
				X2R = r2.ToByteArray()
			};

			ProtocolState = State.Round1Created;
			return dto;
		}

		/// <summary>
		/// Validates the ZKP DTO data received from the other participant during round 1.
		/// </summary>
		/// <param name="round1PayloadReceived">Round1 payload received.</param>
		public void ValidateRound1Received (JpakeRound1 round1PayloadReceived) {
			if (ProtocolState >= State.Round1Validated) {
				throw new InvalidOperationException("Validation already attempted for round 1 payload for " 
					+ ParticipantId);
			}

			PartnerParticipantId = round1PayloadReceived.ParticipantId;
			_GX3 = _domain.Curve.DecodePoint (round1PayloadReceived.GX1);
			_GX4 = _domain.Curve.DecodePoint (round1PayloadReceived.GX2);

			ECPoint X3V = _domain.Curve.DecodePoint (round1PayloadReceived.X1V);
			BigInteger X3R = new BigInteger (round1PayloadReceived.X1R);
			ECPoint X4V = _domain.Curve.DecodePoint (round1PayloadReceived.X2V);
			BigInteger X4R = new BigInteger (round1PayloadReceived.X2R);

			if (VerifyZeroKnowledgeProof (_domain.G, _GX3, X3V, X3R, PartnerParticipantId) == false ||
				VerifyZeroKnowledgeProof (_domain.G, _GX4, X4V, X4R, PartnerParticipantId) == false) 
			{
				throw new CryptoException ("Verification of zero-knowledge proof in round 1 failed.");
			}

			ProtocolState = State.Round1Validated;
		}
	
		/// <summary>
		/// Creates and returns a KZP DTO to send to the other participant during round 2.
		/// </summary>
		/// <param name="round1Sent">Round 1 DTO sent. Null if session has not been interrupted.</param>
		/// <param name="round1Received">Round 1 DTO received. Null if session has not been interrupted.</param>
		/// <param name="passphrase">Passphrase. Null if session has not been interrupted.</param>
		/// <exception cref="InvalidOperationException">
		/// State is invalid for operation requested (in round 1 or 3). 
		/// Method may have been called more than once.
		/// </exception>
		/// <exception cref="CryptoException">
		/// Verification of knowledge proof failed. Possible attempted impersonation / MiTM.
		/// </exception>
		public JpakeRound2 CreateRound2ToSend () {
			if (ProtocolState >= State.Round2Created) {
				throw new InvalidOperationException("Round 2 payload already created for " + ParticipantId);
			} else if (ProtocolState < State.Round1Validated) {
				throw new InvalidOperationException("Round 1 payload must be validated prior to creating Round 2 payload for " 
					+ ParticipantId);
			}

			BigInteger s1 = new BigInteger(_secret);

			ECPoint GA = _GX1.Add(_GX3).Add(_GX4);
			BigInteger x2s1 = _x2.Multiply(s1).Mod(_domain.N);
			ECPoint A = _ecMultiplier.Multiply (GA, x2s1);

			ECPoint X2sV;
			BigInteger X2sR;
			CreateZeroKnowledgeProof (GA, x2s1, A, ParticipantId, 
				out X2sV, out X2sR);

			var dto = new JpakeRound2 {
				ParticipantId = ParticipantId,
				A = A.GetEncoded(),
				X2sV = X2sV.GetEncoded(),
				X2sR = X2sR.ToByteArray()
			};

			ProtocolState = State.Round2Created;
			return dto;
		}


		/// <summary>
		/// Validates the ZKP DTO data received from the other participant during round 2.
		/// </summary>
		/// <remarks>
		/// This DOES NOT indicate possible corrupt / invalid passphrase. 
		/// Execution of rounds 3 and 4 is required for this.
		/// </remarks>
		/// <param name="round2Received">Round 2 DTO received.</param>
		/// <param name="round1Sent">Round 1 DTO sent. Null if session has not been interrupted.</param>
		/// <param name="round1Received">Round 1 DTO received. Null if session has not been interrupted.</param>
		/// <exception cref="InvalidOperationException">
		/// State is invalid for operation requested (in round 1 or 3). 
		/// Method may have been called more than once.
		/// </exception>
		/// <exception cref="CryptoException">
		/// Verification of knowledge proof failed. Possible attempted impersonation / MiTM.
		/// </exception>
		public void ValidateRound2Received (JpakeRound2 round2Received) {
			if (ProtocolState >= State.Round2Validated) {
				throw new InvalidOperationException("Validation already attempted for round 2 payload for " + ParticipantId);
			} else if (ProtocolState < State.Round1Validated) {
				throw new InvalidOperationException("Round 1 payload must be validated prior to validating round 2 payload for " 
					+ ParticipantId);
			}

			ECPoint X4sV = _domain.Curve.DecodePoint (round2Received.X2sV);
			BigInteger X4sR = new BigInteger (round2Received.X2sR);

			_B = _domain.Curve.DecodePoint(round2Received.A);
			// Calculate GB : GX1 + GX3 + GX4 symmetrically
			ECPoint GB = _GX3.Add(_GX1).Add(_GX2);

			if (VerifyZeroKnowledgeProof (GB, _B, X4sV, X4sR, PartnerParticipantId) == false) {
				throw new CryptoException();
			}

			ProtocolState = State.Round2Validated;
		}

		/// <summary>
		/// Calculates the derived shared secret, skipping the key confirmation stage (3). 
		/// A session key must be derived from this key material using a secure key derivation function (KDF).
		/// The KDF used to derive the key is handled externally.
		/// </summary>
		/// <returns>The keying material.</returns>
		/// <param name="secret">Secret.</param>
		public byte[] CalculateKeyingMaterial () {
			return CalculateKeyingMaterialInternal().ToByteArrayUnsigned ();
		}

		protected BigInteger CalculateKeyingMaterialInternal () {
			if (ProtocolState >= State.KeyCalculated) {
				throw new InvalidOperationException("Key already calculated for " + ParticipantId);
			} else if (ProtocolState < State.Round2Validated) {
				throw new InvalidOperationException("Round 2 must be validated prior to creating key for " + ParticipantId);
			}

			BigInteger s1 = new BigInteger(_secret);

			// Clear secret
			_secret.SecureWipe ();
			_secret = null;

			// Prepare BigInteger to be hashed
			var GX4x2s1 = _ecMultiplier.Multiply(_GX4, _x2.Multiply(s1).Mod(_domain.N));
			ECPoint normalised = _ecMultiplier.Multiply(_B.Subtract (GX4x2s1), _x2).Normalize ();

			BigInteger preKey = normalised.AffineXCoord.ToBigInteger();

			// Clear private keys from memory
			_x1 = null;
			_x2 = null;
			_B = null;

			ProtocolState = State.KeyCalculated;

			return Hash (preKey);
		}

		protected BigInteger CalculateMacTag (string participantId, string partnerParticipantId, 
			ECPoint gx1, ECPoint gx2, ECPoint gx3, ECPoint gx4, BigInteger keyingMaterial) 
		{
			_digest.Reset();

			byte[] keyingMaterialBytes = keyingMaterial.ToByteArrayUnsigned ();
			_digest.BlockUpdate (keyingMaterialBytes, 0, keyingMaterialBytes.Length);

			// This constant is used to ensure that the mac key is NOT the same as the derived key.
			byte[] constantBytes = MacKeyConstantBytes;
			_digest.BlockUpdate (constantBytes, 0, constantBytes.Length);

			byte[] macKey = new byte[_digest.DigestSize];
			_digest.DoFinal(macKey, 0);

			// Create and initialise HMAC primitive
			var hmac = new ObscurCore.Cryptography.Authentication.Primitives.HMac(_digest);
			hmac.Init(macKey);

			macKey.SecureWipe ();
			macKey = null;

			// MacData = "KC_1_U" || participantId_Alice || participantId_Bob || gx1 || gx2 || gx3 || gx4.
			byte[] protocolTag = MacTagConstantBytes;
			_digest.BlockUpdate (protocolTag, 0, protocolTag.Length);

			byte[] participantTag = System.Text.Encoding.UTF8.GetBytes (ParticipantId);
			_digest.BlockUpdate (participantTag, 0, participantTag.Length);

			byte[] remoteParticipantTag = System.Text.Encoding.UTF8.GetBytes (PartnerParticipantId);
			_digest.BlockUpdate (remoteParticipantTag, 0, remoteParticipantTag.Length);

			byte[] gx1Bytes = _GX1.GetEncoded ();
			_digest.BlockUpdate (gx1Bytes, 0, gx1Bytes.Length);

			byte[] gx2Bytes = _GX2.GetEncoded ();
			_digest.BlockUpdate (gx2Bytes, 0, gx2Bytes.Length);

			byte[] gx3Bytes = _GX3.GetEncoded ();
			_digest.BlockUpdate (gx3Bytes, 0, gx3Bytes.Length);

			byte[] gx4Bytes = _GX4.GetEncoded ();
			_digest.BlockUpdate (gx4Bytes, 0, gx4Bytes.Length);

			byte[] macTag = new byte[hmac.MacSize];
			hmac.DoFinal(macTag, 0);
			return new BigInteger(macTag);
		}

		protected bool ValidateMacTag (BigInteger receivedTag) {
			BigInteger expectedMacTag = CalculateMacTag (PartnerParticipantId, ParticipantId,
				_GX3, _GX4, _GX1, _GX2, CalculateKeyingMaterialInternal());

			byte[] expectedMacTagBytes = expectedMacTag.ToByteArrayUnsigned ();
			byte[] receivedTagBytes = receivedTag.ToByteArrayUnsigned ();

			return expectedMacTagBytes.SequenceEqualConstantTime(receivedTagBytes);
		}

		/// <summary>
		/// Creates and returns a key confirmation DTO to send to the other participant for round 3.
		/// </summary>
		/// <param name="round1Sent">Round 1 DTO sent. Null if session has not been interrupted.</param>
		/// <param name="round1Received">Round 1 DTO received. Null if session has not been interrupted.</param>
		/// <param name="passphrase">Passphrase. Null if session has not been interrupted.</param>
		/// <exception cref="InvalidOperationException">
		/// State is invalid for operation requested (in round 1 or 3). 
		/// Method may have been called more than once.
		/// </exception>
		/// <exception cref="CryptoException">
		/// Verification of knowledge proof failed. Possible attempted impersonation / MiTM.
		/// </exception>
		public JpakeRound3 CreateRound3ToSend () {
			if (ProtocolState >= State.Round3Created) {
				throw new InvalidOperationException("Round 3 already created for " + ParticipantId);
			} else if (ProtocolState < State.KeyCalculated) {
				throw new InvalidOperationException("Keying material must be calculated prior to creating round 3 for " + ParticipantId);
			}

			var dto = new JpakeRound3 {
				ParticipantId = ParticipantId,
				VerifiedOutput = CalculateMacTag (ParticipantId, PartnerParticipantId, _GX1, _GX2, _GX3, _GX4, 
					CalculateKeyingMaterialInternal()).ToByteArrayUnsigned()
			};

			ProtocolState = State.Round3Created;

			return dto;
		}



		public void ValidateRound3 (JpakeRound3 round3Received) {
			if (ProtocolState >= State.Round3Validated) {
				throw new InvalidOperationException("Validation already attempted for round 3 for" + ParticipantId);
			} else if (ProtocolState < State.KeyCalculated) {
				throw new InvalidOperationException("Keying material must be calculated validated prior to validating round 3 payload for " + ParticipantId);
			}

			BigInteger receivedTag = new BigInteger (round3Received.VerifiedOutput);

			if (ValidateMacTag (receivedTag) == false) {
				throw new CryptoException ("Key confirmation failed - partner MAC tag failed to match expected value.");
			}

			_GX1 = null;
			_GX2 = null;
			_GX3 = null;
			_GX4 = null;

			ProtocolState = State.Round3Validated;
		}

//
//		/*				*
//     * Calculates and returns the key material.
//     * A session key must be derived from this key material using a secure key derivation function (KDF).
//     * The KDF used to derive the key is handled externally (i.e. not by {@link JPAKEParticipant}).
//     * <p/>
//     * <p/>
//     * The keying material will be identical for each participant if and only if
//     * each participant's password is the same.  i.e. If the participants do not
//     * share the same password, then each participant will derive a different key.
//     * Therefore, if you immediately start using a key derived from
//     * the keying material, then you must handle detection of incorrect keys.
//     * If you want to handle this detection explicitly, you can optionally perform
//     * rounds 3 and 4.  See {@link JPAKEParticipant} for details on how to execute
//     * rounds 3 and 4.
//     * <p/>
//     * <p/>
//     * The keying material will be in the range <tt>[0, p-1]</tt>.
//     * <p/>
//     * <p/>
//     * {@link #validateRound2PayloadReceived(JPAKERound2Payload)} must be called prior to this method.
//     * <p/>
//     * <p/>
//     * As a side effect, the internal {@link #password} array is cleared, since it is no longer needed.
//     * <p/>
//     * <p/>
//     * After execution, the {@link #getState() state} will be  {@link #STATE_KEY_CALCULATED}.
//     *
//     * @throws IllegalStateException if called prior to {@link #validateRound2PayloadReceived(JPAKERound2Payload)},
//     * or if called multiple times.
//     */
//		public BigInteger CalculateKeyingMaterial()
//		{
//			if (this.state >= State.KeyCalculated)
//			{
//				throw new InvalidOperationException("Key already calculated for " + participantId);
//			}
//			if (this.state < State.Round2Validated)
//			{
//				throw new InvalidOperationException("Round2 payload must be validated prior to creating key for " + participantId);
//			}
//			BigInteger s = JpakeUtility.CalculateS(password);
//
//			/*						
//         * Clear the password array from memory, since we don't need it anymore.
//         * 
//         * Also set the field to null as a flag to indicate that the key has already been calculated.
//         */
//			Array.Clear (password, 0, password.Length);
//			this.password = null;
//
//			BigInteger keyingMaterial = JpakeUtility.CalculateKeyingMaterial(p, q, GX4, x2, s, b);
//
//			/*						
//         * Clear the ephemeral private key fields as well.
//         * Note that we're relying on the garbage collector to do its job to clean these up.
//         * The old objects will hang around in memory until the garbage collector destroys them.
//         * 
//         * If the ephemeral private keys x1 and x2 are leaked,
//         * the attacker might be able to brute-force the password.
//         */
//			this.x1 = null;
//			this.x2 = null;
//			this.b = null;
//
//			/*						
//         * Do not clear gx* yet, since those are needed by round 3.
//         */
//
//			this.state = State.KeyCalculated;
//
//			return keyingMaterial;
//		}
//
//
//		/*				*
//     * Creates and returns the payload to send to the other participant during round 3.
//     * <p/>
//     * <p/>
//     * See {@link JPAKEParticipant} for more details on round 3.
//     * <p/>
//     * <p/>
//     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_3_CREATED}.
//     *
//     * @param keyingMaterial The keying material as returned from {@link #calculateKeyingMaterial()}.
//     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
//     */
//		public JpakeRound3Payload createRound3PayloadToSend(BigInteger keyingMaterial)
//		{
//			if (this.state >= State.Round3Created)
//			{
//				throw new InvalidOperationException("Round3 payload already created for " + this.participantId);
//			}
//			if (this.state < State.KeyCalculated)
//			{
//				throw new InvalidOperationException("Keying material must be calculated prior to creating Round3 payload for " + this.participantId);
//			}
//
//			BigInteger macTag = JpakeUtility.CalculateMacTag(
//				this.participantId,
//				this.partnerParticipantId,
//				this.GX1,
//				this.GX2,
//				this.GX3,
//				this.GX4,
//				keyingMaterial,
//				this.digest);
//
//			this.state = State.Round3Created;
//
//			return new JpakeRound3Payload(participantId, macTag);
//		}
//
//		/*				*
//     * Validates the payload received from the other participant during round 3.
//     * <p/>
//     * <p/>
//     * See {@link JPAKEParticipant} for more details on round 3.
//     * <p/>
//     * <p/>
//     * After execution, the {@link #getState() state} will be {@link #STATE_ROUND_3_VALIDATED}.
//     *
//     * @param keyingMaterial The keying material as returned from {@link #calculateKeyingMaterial()}.
//     * @throws CryptoException if validation fails.
//     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
//     */
//		public void validateRound3PayloadReceived(JpakeRound3Payload round3PayloadReceived, BigInteger keyingMaterial)
//		{
//			if (this.state >= State.Round3Validated)
//			{
//				throw new InvalidOperationException("Validation already attempted for round3 payload for" + participantId);
//			}
//			if (this.state < State.KeyCalculated)
//			{
//				throw new InvalidOperationException("Keying material must be calculated validated prior to validating Round3 payload for " + this.participantId);
//			}
//			JpakeUtility.ValidateParticipantIdsDiffer(participantId, round3PayloadReceived.GetParticipantId());
//			JpakeUtility.ValidateParticipantIdsEqual(this.partnerParticipantId, round3PayloadReceived.GetParticipantId());
//
//			JpakeUtility.ValidateMacTag(
//				this.participantId,
//				this.partnerParticipantId,
//				this.GX1,
//				this.GX2,
//				this.GX3,
//				this.GX4,
//				keyingMaterial,
//				this.digest,
//				round3PayloadReceived.GetMacTag());
//
//
//			/*						
//         * Clear the rest of the fields.
//         */
//			this.GX1 = null;
//			this.GX2 = null;
//			this.GX3 = null;
//			this.GX4 = null;
//
//			this.state = State.Round3Validated;
//		}

	}
}



