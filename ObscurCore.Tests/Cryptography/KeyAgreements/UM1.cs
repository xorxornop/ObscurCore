using System;
using System.Collections.Generic;
using NUnit.Framework;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Cryptography.KeyAgreements
{
	[TestFixture]
	public class UM1Agreements
	{
		private readonly Dictionary<string, ECTestKPStore> _ecKeypairs = 
			new Dictionary<string, ECTestKPStore>();
		
		private class ECTestKPStore
		{
			public ECKeypair Initiator { get; set; }
			public ECKeypair Responder { get; set; }
		}
		
		[TestFixtureSetUp]
		public void Init () {		
			var curves = Enum.GetNames (typeof(BrainpoolEllipticCurve));
			for (var i = 0; i < curves.Length; i++) {
				_ecKeypairs.Add (curves [i], new ECTestKPStore {
					Initiator = KeypairFactory.GenerateECKeypair(curves[i]),
					Responder = KeypairFactory.GenerateECKeypair(curves[i])
				});
			}

            curves = Enum.GetNames (typeof(Sec2EllipticCurve));
            for (var i = 0; i < curves.Length; i++) {
				_ecKeypairs.Add (curves [i], new ECTestKPStore {
					Initiator = KeypairFactory.GenerateECKeypair(curves[i]),
					Responder = KeypairFactory.GenerateECKeypair(curves[i])
				});
			}

			_ecKeypairs.Add (DjbCurve.Curve25519.ToString(), new ECTestKPStore {
				Initiator = KeypairFactory.GenerateECKeypair(DjbCurve.Curve25519.ToString()),
				Responder = KeypairFactory.GenerateECKeypair(DjbCurve.Curve25519.ToString())
			});

            _ecKeypairs.Add(DjbCurve.Ed25519.ToString(), new ECTestKPStore {
                Initiator = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString()),
                Responder = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString())
            });
		}

		[Test()]
		public void UM1Exchange_Curve25519 () {
			DoUM1Exchange(_ecKeypairs[DjbCurve.Curve25519.ToString()]);
		}

        [Test()]
        public void UM1Exchange_Ed25519()
        {
            DoUM1Exchange(_ecKeypairs[DjbCurve.Ed25519.ToString()]);
        }
		
		[Test()]
		public void UM1Exchange_BrainpoolP160r1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP160r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_BrainpoolP160t1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP160t1.ToString()]);
		}
		
		[Test()]
		public void UM1Exchange_BrainpoolP192r1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP192r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_BrainpoolP192t1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP192t1.ToString()]);
		}
		
        [Test()]
        public void UM1Exchange_BrainpoolP224r1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP224r1.ToString()]);
        }

        [Test()]
		public void UM1Exchange_BrainpoolP224t1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP224t1.ToString()]);
		}
		
		[Test()]
		public void UM1Exchange_BrainpoolP256r1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP256r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_BrainpoolP256t1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP256t1.ToString()]);
		}
		
		[Test()]
		public void UM1Exchange_BrainpoolP320r1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP320r1.ToString()]);
		}

		[Test()]
		public void UM1Exchange_BrainpoolP320t1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP320t1.ToString()]);
		}
		
        [Test()]
        public void UM1Exchange_BrainpoolP384r1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP384r1.ToString()]);
        }

		[Test()]
		public void UM1Exchange_BrainpoolP384t1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP384t1.ToString()]);
		}
		
		[Test()]
		public void UM1Exchange_BrainpoolP512r1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP512r1.ToString()]);
		}

		[Test()]
		public void UM1Exchange_BrainpoolP512t1 () {
			DoUM1Exchange(_ecKeypairs[BrainpoolEllipticCurve.BrainpoolP512t1.ToString()]);
		}
		
        [Test()]
		public void UM1Exchange_Secp192k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp192k1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Secp192r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp192r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Secp224k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp224k1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Secp224r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp224r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Secp256k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp256k1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Secp256r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp256r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Secp384r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp384r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Secp521r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Secp521r1.ToString()]);
		}

		[Test()]
		public void UM1Exchange_Sect163r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect163r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Sect163r2 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect163r2.ToString()]);
		}

		[Test()]
		public void UM1Exchange_Sect193r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect193r1.ToString()]);
		}

		[Test()]
		public void UM1Exchange_Sect192r2 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect193r2.ToString()]);
		}

        [Test()]
        public void UM1Exchange_Sect233k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect233k1.ToString()]);
        }

        [Test()]
		public void UM1Exchange_Sect233r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect233r1.ToString()]);
		}

        [Test()]
		public void UM1Exchange_Sect239k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect239k1.ToString()]);
        }

        [Test()]
		public void UM1Exchange_Sect283k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect283k1.ToString()]);
		}

		[Test()]
		public void UM1Exchange_Sect283r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect283r1.ToString()]);
		}

        [Test()]
        public void UM1Exchange_Sect409k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect409k1.ToString()]);
        }

        [Test()]
		public void UM1Exchange_Sect409r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect409r1.ToString()]);
		}

        [Test()]
        public void UM1Exchange_Sect571k1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect571k1.ToString()]);
        }

        [Test()]
		public void UM1Exchange_Sect571r1 () {
			DoUM1Exchange(_ecKeypairs[Sec2EllipticCurve.Sect571r1.ToString()]);
		}

		private static void DoUM1Exchange(ECTestKPStore keypair) {
			var sw = System.Diagnostics.Stopwatch.StartNew ();

			ECKey ephemeral;
			var initiatorSS = Um1Exchange.Initiate(keypair.Responder.ExportPublicKey(),
				keypair.Initiator.GetPrivateKey(), out ephemeral);
			var responderSS = Um1Exchange.Respond(keypair.Initiator.ExportPublicKey(), 
				keypair.Responder.GetPrivateKey(), ephemeral);

			sw.Stop ();

			Assert.IsTrue(initiatorSS.SequenceEqualShortCircuiting(responderSS));
			Assert.Pass ("{0} ms. Key = {1}", 
				sw.ElapsedMilliseconds, initiatorSS.ToHexString ());
		}
	}
}

