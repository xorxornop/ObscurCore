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
	public class UM1Agreements
	{
		private readonly Dictionary<string, ECTestKPStore> _ecBrainpoolKPs = 
			new Dictionary<string, ECTestKPStore>();
		
		private class ECTestKPStore
		{
			public AsymmetricCipherKeyPair Initiator { get; set; }
			public AsymmetricCipherKeyPair Responder { get; set; }
		}
		
		[TestFixtureSetUp]
		public void Init () {		
			var curves = Enum.GetNames (typeof(BrainpoolECFpCurves));
			for (var i = 1; i < curves.Length; i++) {
			    var domain = Source.GetECDomainParameters(curves[i]);
				var kpInitiator = ECAgreementUtility.GenerateKeyPair (domain);
				var kpResponder = ECAgreementUtility.GenerateKeyPair (domain);
				
				var kpStore = new ECTestKPStore {
					Initiator = kpInitiator,
					Responder = kpResponder
				};
				
				_ecBrainpoolKPs.Add (curves [i], kpStore);
			}
		}
		
		[Test()]
		public void UM1Exchange_160r1 () {
			byte[] initiatorSS, responderSS;
			var context = _ecBrainpoolKPs[BrainpoolECFpCurves.BrainpoolP160r1.ToString()];
            DoUM1Exchange(context.Initiator, context.Responder, out initiatorSS, out responderSS);
			// Compare the shared secret byte sequences
			Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
		
		[Test()]
		public void UM1Exchange_192r1 () {
			byte[] initiatorSS, responderSS;
			var context = _ecBrainpoolKPs[BrainpoolECFpCurves.BrainpoolP192r1.ToString()];
            DoUM1Exchange(context.Initiator, context.Responder, out initiatorSS, out responderSS);
			// Compare the shared secret byte sequences
			Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
		
		[Test()]
		public void UM1Exchange_224r1 () {
			byte[] initiatorSS, responderSS;
			var context = _ecBrainpoolKPs[BrainpoolECFpCurves.BrainpoolP224r1.ToString()];
            DoUM1Exchange(context.Initiator, context.Responder, out initiatorSS, out responderSS);
			// Compare the shared secret byte sequences
			Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
		
		[Test()]
		public void UM1Exchange_256r1 () {
			byte[] initiatorSS, responderSS;
			var context = _ecBrainpoolKPs[BrainpoolECFpCurves.BrainpoolP256r1.ToString()];
            DoUM1Exchange(context.Initiator, context.Responder, out initiatorSS, out responderSS);
			// Compare the shared secret byte sequences
			Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
		
		[Test()]
		public void UM1Exchange_320r1 () {
			byte[] initiatorSS, responderSS;
			var context = _ecBrainpoolKPs[BrainpoolECFpCurves.BrainpoolP320r1.ToString()];
            DoUM1Exchange(context.Initiator, context.Responder, out initiatorSS, out responderSS);
			// Compare the shared secret byte sequences
			Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
		
		[Test()]
		public void UM1Exchange_384r1 () {
			byte[] initiatorSS, responderSS;
			var context = _ecBrainpoolKPs[BrainpoolECFpCurves.BrainpoolP384r1.ToString()];
            DoUM1Exchange(context.Initiator, context.Responder, out initiatorSS, out responderSS);
			// Compare the shared secret byte sequences
			Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
		
		[Test()]
		public void UM1Exchange_512r1 () {
			byte[] initiatorSS, responderSS;
			var context = _ecBrainpoolKPs[BrainpoolECFpCurves.BrainpoolP512r1.ToString()];
            DoUM1Exchange(context.Initiator, context.Responder, out initiatorSS, out responderSS);
			// Compare the shared secret byte sequences
			Assert.IsTrue(initiatorSS.SequenceEqual(responderSS));
		}
		
		private static void DoUM1Exchange(AsymmetricCipherKeyPair kpInitiator, AsymmetricCipherKeyPair kpResponder, out byte[] initiatorSS, out byte[] responderSS) {
			var initiator = new UM1ExchangeInitiator((ECPublicKeyParameters) kpResponder.Public, (ECPrivateKeyParameters) kpInitiator.Private);
			var responder = new UM1ExchangeResponder((ECPublicKeyParameters) kpInitiator.Public, (ECPrivateKeyParameters) kpResponder.Private);
			
			ECPublicKeyParameters ephemeral;
			initiatorSS = initiator.CalculateSharedSecret(out ephemeral);
			responderSS = responder.CalculateSharedSecret(ephemeral);
		}
	}
}

