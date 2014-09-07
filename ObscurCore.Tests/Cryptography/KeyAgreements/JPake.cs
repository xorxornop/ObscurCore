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

using NUnit.Framework;

using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyAgreement.Primitives;
using ObscurCore.Cryptography.Authentication;

namespace ObscurCore.Tests.Cryptography.KeyAgreements
{
	[TestFixture]
	public class JPake
	{
		[Test]
		public void BrainpoolP256t1_Blake2B256() 
        {
			TestEcJPake (BrainpoolEllipticCurve.BrainpoolP256t1.ToString (), HashFunction.Blake2B256);
		}

        [Test]
        public void BrainpoolP256t1_Keccak256()
        {
            TestEcJPake(BrainpoolEllipticCurve.BrainpoolP256t1.ToString(), HashFunction.Keccak256);
        }

        [Test]
        public void BrainpoolP384t1_Blake2B384()
        {
            TestEcJPake(BrainpoolEllipticCurve.BrainpoolP384t1.ToString(), HashFunction.Blake2B384);
        }

        [Test]
        public void BrainpoolP384t1_Keccak384()
        {
            TestEcJPake(BrainpoolEllipticCurve.BrainpoolP384t1.ToString(), HashFunction.Keccak384);
        }

		[Test]
        public void BrainpoolP512t1_Blake2B512()
        {
			TestEcJPake (BrainpoolEllipticCurve.BrainpoolP512t1.ToString (), HashFunction.Blake2B512);
		}

        [Test]
        public void BrainpoolP512t1_Keccak512()
        {
            TestEcJPake(BrainpoolEllipticCurve.BrainpoolP512t1.ToString(), HashFunction.Keccak512);
        }

        [Test]
        public void Secp192r1_Tiger()
        {
            TestEcJPake(Sec2EllipticCurve.Secp192r1.ToString(), HashFunction.Tiger);
        }

        [Test]
        public void Secp192k1_Tiger()
        {
            TestEcJPake(Sec2EllipticCurve.Secp192k1.ToString(), HashFunction.Tiger);
        }

        [Test]
        public void Secp256k1_Blake2B256()
        {
            TestEcJPake(Sec2EllipticCurve.Secp256k1.ToString(), HashFunction.Blake2B256);
        }

        [Test]
        public void Secp256k1_Keccak256()
        {
            TestEcJPake(Sec2EllipticCurve.Secp256k1.ToString(), HashFunction.Keccak256);
        }

        [Test]
        public void Secp256k1_Sha256()
        {
            TestEcJPake(Sec2EllipticCurve.Secp256k1.ToString(), HashFunction.Sha256);
        }

        [Test]
        public void Secp384r1_Blake2B384()
        {
            TestEcJPake(Sec2EllipticCurve.Secp384r1.ToString(), HashFunction.Blake2B384);
        }

        [Test]
        public void Secp384r1_Keccak384()
        {
            TestEcJPake(Sec2EllipticCurve.Secp384r1.ToString(), HashFunction.Keccak384);
        }

        [Test]
        public void Secp521r1_Blake2B512() 
        {
            TestEcJPake(Sec2EllipticCurve.Secp521r1.ToString(), HashFunction.Blake2B512);
        }

        [Test]
        public void Secp521r1_Keccak512()
        {
            TestEcJPake(Sec2EllipticCurve.Secp521r1.ToString(), HashFunction.Keccak512);
        }

        [Test]
        public void Secp521r1_Sha512()
        {
            TestEcJPake(Sec2EllipticCurve.Secp521r1.ToString(), HashFunction.Sha512);
        }

		private static void TestEcJPake(string curveName, HashFunction hashFunction) {
			const string password = "green eggs and ham";
			var ecParams = EcInformationStore.GetECCurveData(curveName).GetParameters();
			var digest = AuthenticatorFactory.CreateHashPrimitive(hashFunction);

			var alice = new ECJpakeSession("ObscurCore_P0", password, ecParams, digest, StratCom.EntropySupplier);
			var bob = new ECJpakeSession("ObscurCore_P1", password, ecParams, digest, StratCom.EntropySupplier);

			var sw = System.Diagnostics.Stopwatch.StartNew();

            // Round 1
			var aliceR1 = alice.CreateRound1ToSend();
			var bobR1 = bob.CreateRound1ToSend();
			alice.ValidateRound1Received(bobR1);
			bob.ValidateRound1Received(aliceR1);
            // Round 2
			var aliceR2 = alice.CreateRound2ToSend();
			var bobR2 = bob.CreateRound2ToSend();
			alice.ValidateRound2Received(bobR2);
			bob.ValidateRound2Received(aliceR2);
            // Round 3 (key confirmation)
            byte[] aliceKey, bobKey;
			var aliceR3 = alice.CreateRound3ToSend();
			var bobR3 = bob.CreateRound3ToSend();
			alice.ValidateRound3Received(bobR3, out aliceKey);
			bob.ValidateRound3Received(aliceR3, out bobKey);

			sw.Stop();

			Assert.IsTrue(aliceKey.SequenceEqualShortCircuiting(bobKey), "Keys produced ARE NOT equal! Protocol implementation is broken.");

			Assert.Pass("{0} ms.\nKey = {1}", sw.ElapsedMilliseconds, aliceKey.ToHexString());
		}
	}
}
