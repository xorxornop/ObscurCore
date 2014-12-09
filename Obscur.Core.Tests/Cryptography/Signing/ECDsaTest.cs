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

using NUnit.Framework;
using Obscur.Core.Cryptography.Authentication;
using Obscur.Core.Cryptography.Authentication.Primitives;
using Obscur.Core.Cryptography.Information;
using Obscur.Core.Cryptography.Information.EllipticCurve;
using Obscur.Core.Cryptography.KeyAgreement;
using Obscur.Core.Cryptography.Signing.Primitives;
using Obscur.Core.Cryptography.Support.Math;
using Obscur.Core.DTO;
using Obscur.Core.Support;

namespace Obscur.Core.Tests.Cryptography.Signing
{
    /// <summary>
    ///     Tests are taken from RFC 6979 -
    ///     "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm
    ///     (ECDSA)".
    /// </summary>
    internal class ECDsaTest
    {
        public static readonly byte[] SAMPLE = Hex.Decode("73616d706c65"); // "sample"
        public static readonly byte[] TEST = Hex.Decode("74657374"); // "test"

        #region P192

        [Test]
        public void NIST_P192_SHA1()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp192r1);
            const string key = "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4";
            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(
                new Sha1Digest(),
                privKey,
                new BigInteger("98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF", 16),
                new BigInteger("57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64", 16));

            DoTestHMacDetECDsaTest(
                new Sha1Digest(),
                privKey,
                new BigInteger("0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D", 16),
                new BigInteger("EB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7", 16));
        }

        [Test]
        public void NIST_P192_SHA256()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp192r1);
            const string key = "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4";
            ECKey privKey = GetPrivKey(curve, key);


            DoTestHMacDetECDsaSample(new Sha256Digest(), privKey,
                new BigInteger("4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55", 16),
                new BigInteger("CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85", 16));

            DoTestHMacDetECDsaTest(new Sha256Digest(), privKey,
                new BigInteger("3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE", 16),
                new BigInteger("5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F", 16));
        }

        [Test]
        public void NIST_P192_SHA512()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp192r1);
            const string key = "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4";
            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(
                new Sha1Digest(),
                privKey,
                new BigInteger("98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF", 16),
                new BigInteger("57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64", 16));

            DoTestHMacDetECDsaTest(
                new Sha1Digest(),
                privKey,
                new BigInteger("0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D", 16),
                new BigInteger("EB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7", 16));
        }

        #endregion

        #region P256

        [Test]
        public void NIST_P256_SHA1()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp256r1);
            const string key = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(new Sha1Digest(), privKey,
                new BigInteger("61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32", 16),
                new BigInteger("6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB", 16));
            DoTestHMacDetECDsaTest(new Sha1Digest(), privKey,
                new BigInteger("0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89", 16),
                new BigInteger("01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1", 16));
        }

        [Test]
        public void NIST_P256_SHA256()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp256r1);
            const string key = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(new Sha256Digest(), privKey,
                new BigInteger("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16),
                new BigInteger("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 16));
            DoTestHMacDetECDsaTest(new Sha256Digest(), privKey,
                new BigInteger("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", 16),
                new BigInteger("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", 16));
        }

        [Test]
        public void NIST_P256_SHA512()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp256r1);
            const string key = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(new Sha512Digest(), privKey,
                new BigInteger("8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00", 16),
                new BigInteger("2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE", 16));
            DoTestHMacDetECDsaTest(new Sha512Digest(), privKey,
                new BigInteger("461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04", 16),
                new BigInteger("39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55", 16));
        }

        #endregion

        #region P521

        [Test]
        public void NIST_P521_SHA1()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp521r1);
            const string key = "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C" +
                               "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83" +
                               "538";
            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(new Sha1Digest(), privKey,
                new BigInteger("0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910" +
                               "FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D" +
                               "75D", 16),
                new BigInteger("0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D" +
                               "5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5" +
                               "D16", 16));
            DoTestHMacDetECDsaTest(new Sha1Digest(), privKey,
                new BigInteger("13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0" +
                               "693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0" +
                               "367", 16),
                new BigInteger("1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90" +
                               "F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC91679" +
                               "7FF", 16));
        }

        [Test]
        public void NIST_P521_SHA256()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp521r1);
            const string key = "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C" +
                               "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83" +
                               "538";

            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(
                new Sha256Digest(),
                privKey, new BigInteger("1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659" +
                                        "D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E" +
                                        "1A7", 16),
                new BigInteger("04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916" +
                               "E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7E" +
                               "CFC", 16));
            DoTestHMacDetECDsaTest(
                new Sha256Digest(),
                privKey, new BigInteger("00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D807104" +
                                        "2EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656" +
                                        "AA8", 16),
                new BigInteger("0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9" +
                               "FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694" +
                               "E86", 16));
        }

        [Test]
        public void NIST_P521_SHA512()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Secp521r1);
            const string key = "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C" +
                               "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83" +
                               "538";

            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(
                new Sha512Digest(),
                privKey, new BigInteger("0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1" +
                                        "74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37" +
                                        "7FA", 16),
                new BigInteger("0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2" +
                               "82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A" +
                               "67A", 16));

            DoTestHMacDetECDsaTest(
                new Sha512Digest(),
                privKey, new BigInteger("13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10" +
                                        "CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47E" +
                                        "E6D", 16),
                new BigInteger("1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78" +
                               "A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4D" +
                               "CE3", 16));
        }

        #endregion

        #region B571

        [Test]
        public void NIST_B571_SHA1()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Sect571r1);
            const string key = "028A04857F24C1C082DF0D909C0E72F453F2E2340CCB071F0E389BCA2575DA19" +
                               "124198C57174929AD26E348CF63F78D28021EF5A9BF2D5CBEAF6B7CCB6C4DA82" +
                               "4DD5C82CFB24E11";

            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(new Sha1Digest(), privKey,
                new BigInteger("147D3EB0EDA9F2152DFD014363D6A9CE816D7A1467D326A625FC4AB0C786E1B7" +
                               "4DDF7CD4D0E99541391B266C704BB6B6E8DCCD27B460802E0867143727AA4155" +
                               "55454321EFE5CB6", 16),
                new BigInteger("17319571CAF533D90D2E78A64060B9C53169AB7FC908947B3EDADC54C79CCF0A" +
                               "7920B4C64A4EAB6282AFE9A459677CDA37FD6DD50BEF18709590FE18B923BDF7" +
                               "4A66B189A850819", 16));
            DoTestHMacDetECDsaTest(new Sha1Digest(), privKey,
                new BigInteger("133F5414F2A9BC41466D339B79376038A64D045E5B0F792A98E5A7AA87E0AD01" +
                               "6419E5F8D176007D5C9C10B5FD9E2E0AB8331B195797C0358BA05ECBF24ACE59" +
                               "C5F368A6C0997CC", 16),
                new BigInteger("3D16743AE9F00F0B1A500F738719C5582550FEB64689DA241665C4CE4F328BA0" +
                               "E34A7EF527ED13BFA5889FD2D1D214C11EB17D6BC338E05A56F41CAFF1AF7B8D" +
                               "574DB62EF0D0F21", 16));
        }

        [Test]
        public void NIST_B571_SHA256()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Sect571r1);
            const string key = "028A04857F24C1C082DF0D909C0E72F453F2E2340CCB071F0E389BCA2575DA19" +
                               "124198C57174929AD26E348CF63F78D28021EF5A9BF2D5CBEAF6B7CCB6C4DA82" +
                               "4DD5C82CFB24E11";

            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(new Sha256Digest(), privKey,
                new BigInteger("213EF9F3B0CFC4BF996B8AF3A7E1F6CACD2B87C8C63820000800AC787F17EC99" +
                               "C04BCEDF29A8413CFF83142BB88A50EF8D9A086AF4EB03E97C567500C21D8657" +
                               "14D832E03C6D054", 16),
                new BigInteger("3D32322559B094E20D8935E250B6EC139AC4AAB77920812C119AF419FB62B332" +
                               "C8D226C6C9362AE3C1E4AABE19359B8428EA74EC8FBE83C8618C2BCCB6B43FBA" +
                               "A0F2CCB7D303945", 16));
            DoTestHMacDetECDsaTest(new Sha256Digest(), privKey,
                new BigInteger("184BC808506E11A65D628B457FDA60952803C604CC7181B59BD25AEE1411A66D" +
                               "12A777F3A0DC99E1190C58D0037807A95E5080FA1B2E5CCAA37B50D401CFFC34" +
                               "17C005AEE963469", 16),
                new BigInteger("27280D45F81B19334DBDB07B7E63FE8F39AC7E9AE14DE1D2A6884D2101850289" +
                               "D70EE400F26ACA5E7D73F534A14568478E59D00594981ABE6A1BA18554C13EB5" +
                               "E03921E4DC98333", 16));
        }

        [Test]
        public void NIST_B571_SHA512()
        {
            EcCurveInformation curve = EcInformationStore.GetECCurveData(Sec2EllipticCurve.Sect571r1);
            const string key = "028A04857F24C1C082DF0D909C0E72F453F2E2340CCB071F0E389BCA2575DA19" +
                               "124198C57174929AD26E348CF63F78D28021EF5A9BF2D5CBEAF6B7CCB6C4DA82" +
                               "4DD5C82CFB24E11";

            ECKey privKey = GetPrivKey(curve, key);

            DoTestHMacDetECDsaSample(
                new Sha512Digest(),
                privKey,
                new BigInteger("1C26F40D940A7EAA0EB1E62991028057D91FEDA0366B606F6C434C361F04E545" +
                               "A6A51A435E26416F6838FFA260C617E798E946B57215284182BE55F29A355E60" +
                               "24FE32A47289CF0", 16),
                new BigInteger("3691DE4369D921FE94EDDA67CB71FBBEC9A436787478063EB1CC778B3DCDC1C4" +
                               "162662752D28DEEDF6F32A269C82D1DB80C87CE4D3B662E03AC347806E3F19D1" +
                               "8D6D4DE7358DF7E", 16));
            DoTestHMacDetECDsaTest(
                new Sha512Digest(),
                privKey,
                new BigInteger("2AA1888EAB05F7B00B6A784C4F7081D2C833D50794D9FEAF6E22B8BE728A2A90" +
                               "BFCABDC803162020AA629718295A1489EE7ED0ECB8AAA197B9BDFC49D18DDD78" +
                               "FC85A48F9715544", 16),
                new BigInteger("0AA5371FE5CA671D6ED9665849C37F394FED85D51FEF72DA2B5F28EDFB2C6479" +
                               "CA63320C19596F5E1101988E2C619E302DD05112F47E8823040CE540CD3E90DC" +
                               "F41DBC461744EE9", 16));
        }

        #endregion

        [Test]
        public void DJB_Ed25519_SHA256()
        {
            byte[] data = TEST;

            var digest = new Sha256Digest();
            var m = new byte[digest.OutputSize];
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(m, 0);

            ECKeypair keypair = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString());
            byte[] sig = Ed25519.Sign(m, keypair.EncodedPrivateKey);
            bool good = Ed25519.Verify(sig, m, keypair.EncodedPublicKey);

            Assert.IsTrue(good);
        }

        [Test]
        public void DJB_Ed25519_Keccak256()
        {
            byte[] data = TEST;

            var digest = new KeccakDigest(256);
            var m = new byte[digest.OutputSize];
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(m, 0);

            ECKeypair keypair = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString());
            byte[] sig = Ed25519.Sign(m, keypair.EncodedPrivateKey);
            bool good = Ed25519.Verify(sig, m, keypair.EncodedPublicKey);

            Assert.IsTrue(good);
        }

        [Test]
        public void DJB_Ed25519_Blake2B256()
        {
            byte[] data = TEST;

            var digest = new Blake2BDigest(256);
            var m = new byte[digest.OutputSize];
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(m, 0);

            ECKeypair keypair = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString());
            byte[] sig = Ed25519.Sign(m, keypair.EncodedPrivateKey);
            bool good = Ed25519.Verify(sig, m, keypair.EncodedPublicKey);

            Assert.IsTrue(good);
        }

        [Test]
        public void DJB_Ed25519_SHA512()
        {
            byte[] data = TEST;

            var digest = new Sha512Digest();
            var m = new byte[digest.OutputSize];
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(m, 0);

            ECKeypair keypair = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString());
            byte[] sig = Ed25519.Sign(m, keypair.EncodedPrivateKey);
            bool good = Ed25519.Verify(sig, m, keypair.EncodedPublicKey);

            Assert.IsTrue(good);
        }

        [Test]
        public void DJB_Ed25519_Keccak512()
        {
            byte[] data = TEST;

            var digest = new KeccakDigest(512);
            var m = new byte[digest.OutputSize];
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(m, 0);

            ECKeypair keypair = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString());
            byte[] sig = Ed25519.Sign(m, keypair.EncodedPrivateKey);
            bool good = Ed25519.Verify(sig, m, keypair.EncodedPublicKey);

            Assert.IsTrue(good);
        }

        [Test]
        public void DJB_Ed25519_Blake2B512()
        {
            byte[] data = TEST;

            var digest = new Blake2BDigest(512);
            var m = new byte[digest.OutputSize];
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(m, 0);

            ECKeypair keypair = KeypairFactory.GenerateECKeypair(DjbCurve.Ed25519.ToString());
            byte[] sig = Ed25519.Sign(m, keypair.EncodedPrivateKey);
            bool good = Ed25519.Verify(sig, m, keypair.EncodedPublicKey);

            Assert.IsTrue(good);
        }


        private static ECKey GetPrivKey(EcCurveInformation curve, string encodedKey)
        {
            var bi = new BigInteger(encodedKey, 16);

            var privKey = new ECKey {
                PublicComponent = false,
                CurveProviderName = EcInformationStore.GetProvider(curve.Name),
                CurveName = curve.Name,
                EncodedKey = bi.ToByteArray()
            };

            return privKey;
        }

        private void DoTestHMacDetECDsaSample(IHash digest, ECKey privKey, BigInteger r, BigInteger s)
        {
            DoTestHMacDetECDsa(digest, SAMPLE, privKey, r, s);
        }

        private void DoTestHMacDetECDsaTest(IHash digest, ECKey privKey, BigInteger r, BigInteger s)
        {
            DoTestHMacDetECDsa(digest, TEST, privKey, r, s);
        }

        private void DoTestHMacDetECDsa(IHash digest, byte[] data, ECKey privKey, BigInteger r, BigInteger s)
        {
            var m = new byte[digest.OutputSize];

            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(m, 0);

            var signer = new ECDsaSigner(true, privKey, null, new HmacDsaKCalculator(digest));

            BigInteger rOut, sOut;
            signer.GenerateSignature(m, out rOut, out sOut);

            if (!r.Equals(rOut)) {
                Assert.Fail("r value wrong");
            }
            if (!s.Equals(sOut)) {
                Assert.Fail("s value wrong");
            }
        }
    }
}
