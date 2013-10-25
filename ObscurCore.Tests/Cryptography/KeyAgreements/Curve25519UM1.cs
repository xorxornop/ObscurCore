using System;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.Support;

namespace ObscurCore.Tests.Cryptography.KeyAgreements
{
	[TestFixture]
	public class Curve25519UM1Agreements
	{
	    private byte[] _publicKeySender, _publicKeyRecipient;
	    private byte[] _privateKeySender, _privateKeyRecipient;
		
		[TestFixtureSetUp]
		public void Init () {
		    var privEntropy = new byte[32];
		    StratCom.EntropySource.NextBytes(privEntropy);
		    _privateKeySender = Curve25519.CreatePrivateKey(privEntropy);
		    _publicKeySender = Curve25519.CreatePublicKey(_privateKeySender);

            StratCom.EntropySource.NextBytes(privEntropy);
            _privateKeyRecipient = Curve25519.CreatePrivateKey(privEntropy);
		    _publicKeyRecipient = Curve25519.CreatePublicKey(_privateKeyRecipient);
		}
		
		[Test]
		public void DoAgreement () {
		    byte[] initiatorSS, responderSS, eph;

		    initiatorSS = Curve25519UM1Exchange.Initiate(_publicKeyRecipient, _privateKeySender, out eph);
		    responderSS = Curve25519UM1Exchange.Respond(_publicKeySender, _privateKeyRecipient, eph);

		    // Compare the shared secret byte sequences
		    Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
	}
}

