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
using System.IO;
using System.Linq;
using System.Text;
using ObscurCore.Cryptography;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Authentication.Primitives;
using ObscurCore.Cryptography.Authentication.Primitives.SHA3;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Block.Modes;
using ObscurCore.Cryptography.Ciphers.Block.Padding;
using ObscurCore.Cryptography.Ciphers.Block.Primitives;
using ObscurCore.Cryptography.Ciphers.Block.Primitives.Parameters;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.Ciphers.Stream.Primitives;
using ObscurCore.Cryptography.Entropy;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.Cryptography.KeyAgreement;
using ObscurCore.Cryptography.KeyDerivation;
using ObscurCore.Cryptography.Support;
using ObscurCore.Cryptography.Support.Math;
using ObscurCore.Cryptography.Support.Math.EllipticCurve;
using ObscurCore.DTO;
using ObscurCore.Packaging;

namespace ObscurCore
{
    /// <summary>
    /// Creation/factory class. Instantiates and initialises core objects.
    /// </summary>
    public static class Source
    {
        private readonly static IDictionary<SymmetricBlockCipher, Func<int, IBlockCipher>> EngineInstantiatorsBlock =
            new Dictionary<SymmetricBlockCipher, Func<int, IBlockCipher>>();
        private readonly static IDictionary<SymmetricStreamCipher, Func<IStreamCipher>> EngineInstantiatorsStream =
            new Dictionary<SymmetricStreamCipher, Func<IStreamCipher>>();

        private readonly static IDictionary<BlockCipherMode, Func<IBlockCipher, int, IBlockCipher>> ModeInstantiatorsBlock =
            new Dictionary<BlockCipherMode, Func<IBlockCipher, int, IBlockCipher>>();

        private readonly static IDictionary<BlockCipherPadding, Func<IBlockCipherPadding>> PaddingInstantiators =
            new Dictionary<BlockCipherPadding, Func<IBlockCipherPadding>>();

        private readonly static IDictionary<KeyDerivationFunction, Func<int, byte[], IKdfFunction>> KdfInstantiators =
			new Dictionary<KeyDerivationFunction, Func<int, byte[], IKdfFunction>>();
		
		private readonly static IDictionary<KeyDerivationFunction, Func<byte[], byte[], int, byte[], byte[]>> KdfStatics =
			new Dictionary<KeyDerivationFunction, Func<byte[], byte[], int, byte[], byte[]>>();

        private readonly static IDictionary<CsPseudorandomNumberGenerator, Func<byte[], Csprng>> PrngInstantiators =
			new Dictionary<CsPseudorandomNumberGenerator, Func<byte[], Csprng>>();

        private readonly static IDictionary<HashFunction, Func<IDigest>> DigestInstantiators =
			new Dictionary<HashFunction, Func<IDigest>>();

        private readonly static IDictionary<MacFunction, Func<IMac>> MacInstantiators =
			new Dictionary<MacFunction, Func<IMac>>();

        private readonly static IDictionary<string, Func<ECDomainParameters>> EcParameters =
			new Dictionary<string, Func<ECDomainParameters>>();

        // Packaging related

		private readonly static IDictionary<PayloadLayoutScheme, Func<bool, Stream, Manifest, 
			IPayloadConfiguration, PayloadMux>> PayloadLayoutModuleInstantiators = new Dictionary<PayloadLayoutScheme, 
		Func<bool, Stream, Manifest, IPayloadConfiguration, PayloadMux>>();

        static Source() {
            // ######################################## ENGINES ########################################
            // Block engines
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Aes, blockSize => new AesFastEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Blowfish, blockSize => new BlowfishEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Cast5, blockSize => new Cast5Engine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Cast6, blockSize => new Cast6Engine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Camellia, blockSize => new CamelliaEngine());
#if INCLUDE_GOST28147
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Gost28147, blockSize => new Gost28147Engine());
#endif
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Idea, blockSize => new IdeaEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Noekeon, blockSize => new NoekeonEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Rc6, blockSize => new Rc6Engine());
#if INCLUDE_RIJNDAEL
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.Rijndael, blockSize => new RijndaelEngine(blockSize));
#endif
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Serpent, blockSize => new SerpentEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.TripleDes, blockSize => new DesEdeEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCipher.Twofish, blockSize => new TwofishEngine());

            // Stream engines
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Hc128, () => new Hc128Engine());
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Hc256, () => new Hc256Engine());
#if INCLUDE_ISAAC
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Isaac, () => new IsaacEngine());
#endif
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Rabbit, () => new RabbitEngine());
#if INCLUDE_RC4
            _engineInstantiatorsStream.Add(SymmetricStreamCipher.Rc4, () => new Rc4Engine());
#endif
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Salsa20, () => new Salsa20Engine());
            EngineInstantiatorsStream.Add(SymmetricStreamCipher.Sosemanuk, () => new SosemanukEngine());
#if INCLUDE_VMPC
            EngineInstantiatorsBlock.Add(SymmetricStreamCiphers.VMPC, () => new VMPCEngine());
            EngineInstantiatorsBlock.Add(SymmetricStreamCiphers.VMPC_KSA3, () => new VMPCKSA3Engine());
#endif

            // ######################################## BLOCK MODES ########################################
            ModeInstantiatorsBlock.Add(BlockCipherMode.Cbc, (cipher, size) => new CbcBlockCipher(cipher));
            ModeInstantiatorsBlock.Add(BlockCipherMode.Cfb, (cipher, size) => new CfbBlockCipher(cipher, size));
            ModeInstantiatorsBlock.Add(BlockCipherMode.Ctr, (cipher, size) => new SicBlockCipher(cipher));
            // CTS is not properly supported here...
            // Interim solution is just to return a CBC mode cipher, then it can be transformed into a CTS cipher afterwards. 
            // The return type is non-compatible :( .
            ModeInstantiatorsBlock.Add(BlockCipherMode.CtsCbc, (cipher, size) => new CbcBlockCipher(cipher));
            ModeInstantiatorsBlock.Add(BlockCipherMode.Ofb, (cipher, size) => new OfbBlockCipher(cipher, size));

            // ######################################## PADDING ########################################

            PaddingInstantiators.Add(BlockCipherPadding.Iso10126D2, () => new Iso10126D2Padding());
            PaddingInstantiators.Add(BlockCipherPadding.Iso7816D4, () => new Iso7816D4Padding());
            PaddingInstantiators.Add(BlockCipherPadding.Pkcs7, () => new Iso10126D2Padding());
            PaddingInstantiators.Add(BlockCipherPadding.Tbc, () => new Iso10126D2Padding());
            PaddingInstantiators.Add(BlockCipherPadding.X923, () => new Iso10126D2Padding());

            // ######################################## KEY DERIVATION ########################################

            KdfInstantiators.Add(KeyDerivationFunction.Pbkdf2, (outputSize, config) => new Pbkdf2Module(outputSize, config));
			KdfInstantiators.Add(KeyDerivationFunction.Scrypt, (outputSize, config) => new ScryptModule(outputSize, config));
			
			KdfStatics.Add(KeyDerivationFunction.Pbkdf2, Pbkdf2Module.DeriveKeyWithConfig);
			KdfStatics.Add(KeyDerivationFunction.Scrypt, ScryptModule.DeriveKeyWithConfig);

            // ######################################## PRNG ########################################

            PrngInstantiators.Add(CsPseudorandomNumberGenerator.Salsa20, config => new Salsa20Generator(config));
			PrngInstantiators.Add(CsPseudorandomNumberGenerator.Sosemanuk, config => new SosemanukGenerator(config));

            // ######################################## HASHING ########################################

            DigestInstantiators.Add(HashFunction.Blake2B256, () => new Blake2BDigest(256, true));
			DigestInstantiators.Add(HashFunction.Blake2B384, () => new Blake2BDigest(384, true));
			DigestInstantiators.Add(HashFunction.Blake2B512, () => new Blake2BDigest(512, true));

			DigestInstantiators.Add(HashFunction.Keccak224, () => new KeccakDigest(224, true));
			DigestInstantiators.Add(HashFunction.Keccak256, () => new KeccakDigest(256, true));
			DigestInstantiators.Add(HashFunction.Keccak384, () => new KeccakDigest(384, true));
			DigestInstantiators.Add(HashFunction.Keccak512, () => new KeccakDigest(512, true));

#if INCLUDE_SHA1
            DigestInstantiators.Add(HashFunction.Sha1, () => new Sha1Digest());
#endif
            DigestInstantiators.Add(HashFunction.Sha256, () => new Sha256Digest());
            DigestInstantiators.Add(HashFunction.Sha512, () => new Sha512Digest());

            DigestInstantiators.Add(HashFunction.Ripemd160, () => new RipeMD160Digest());

            DigestInstantiators.Add(HashFunction.Tiger, () => new TigerDigest());

            DigestInstantiators.Add(HashFunction.Whirlpool, () => new WhirlpoolDigest());

            // ######################################## MAC ########################################

            MacInstantiators.Add(MacFunction.Blake2B256, () => new Blake2BMac(256, true));
			MacInstantiators.Add(MacFunction.Blake2B384, () => new Blake2BMac(384, true));
			MacInstantiators.Add(MacFunction.Blake2B512, () => new Blake2BMac(512, true));

			MacInstantiators.Add(MacFunction.Keccak224, () => new KeccakMac(224, true));
			MacInstantiators.Add(MacFunction.Keccak256, () => new KeccakMac(256, true));
			MacInstantiators.Add(MacFunction.Keccak384, () => new KeccakMac(384, true));
			MacInstantiators.Add(MacFunction.Keccak512, () => new KeccakMac(512, true));

			MacInstantiators.Add(MacFunction.Poly1305, () => new Poly1305Mac());

            // ######################################## EC ########################################

            // Domain parameter function: p/q, A, B, G, n, h/i (cofactor), S (seed)
            var domainFuncG = new Func<BigInteger, BigInteger, BigInteger, string, BigInteger, BigInteger, string,
                ECDomainParameters>((p, A, B, G, n, h, S) =>
                {
                    var curve = new FpCurve(p, A, B);
			        return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), n, h, S.HexToBinary());
                });

            var domainFuncGxy = new Func<BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, string,
                ECDomainParameters>((p, A, B, Gx, Gy, n, h, S) =>
                {
                    var curve = new FpCurve(p, A, B);
			        return new ECDomainParameters(curve, curve.CreatePoint(Gx, Gy, false), n, h, S.HexToBinary());
                });

            // Add curves over GF(p)

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP160r1.ToString(), () => domainFuncGxy(
                new BigInteger("E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16), // q
                new BigInteger("340E7BE2A280EB74E2BE61BADA745D97E8F7C300", 16), // a
                new BigInteger("1E589A8595423412134FAA2DBDEC95C8D8675E58", 16), // b
                new BigInteger("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", 16), // x
                new BigInteger("1667CB477A1A8EC338F94741669C976316DA6321", 16), // y
                new BigInteger("E95E4A5F737059DC60DF5991D45029409E60FC09", 16), // n
                BigInteger.One,
                null
                ));

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP160t1.ToString(), () => domainFuncGxy(
                new BigInteger("E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16), // q
                new BigInteger("E95E4A5F737059DC60DFC7AD95B3D8139515620C", 16), // a
                new BigInteger("7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380", 16), // b
                new BigInteger("B199B13B9B34EFC1397E64BAEB05ACC265FF2378", 16), // x
                new BigInteger("ADD6718B7C7C1961F0991B842443772152C9E0AD", 16), // y
                new BigInteger("E95E4A5F737059DC60DF5991D45029409E60FC09", 16), // n
                BigInteger.One,
                null
                ));

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP192r1.ToString(), () => domainFuncGxy(
                new BigInteger("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297", 16), // q
                new BigInteger("6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF", 16), // a
                new BigInteger("469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9", 16), // b
                new BigInteger("C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6", 16), // x
                new BigInteger("14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F", 16), // y
                new BigInteger("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1", 16), // n
                BigInteger.One,
                null
                ));

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP192t1.ToString(), () => domainFuncGxy(
                new BigInteger("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297", 16), // q
                new BigInteger("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294", 16), // a
                new BigInteger("13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79", 16), // b
                new BigInteger("3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129", 16), // x
                new BigInteger("97E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9", 16), // y
                new BigInteger("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1", 16), // n
                BigInteger.One,
                null
                ));

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP224r1.ToString(), () => domainFuncGxy(
                new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", 16), // q
                new BigInteger("68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43", 16), // a
                new BigInteger("2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B", 16), // b
                new BigInteger("0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D", 16), // x
                new BigInteger("58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD", 16), // y
                new BigInteger("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", 16), // n
                BigInteger.One,
                null
                ));

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP224t1.ToString(), () => domainFuncGxy(
                new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", 16), // q
                new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC", 16), // a
                new BigInteger("4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D", 16), // b
                new BigInteger("6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580", 16), // x
                new BigInteger("374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C", 16), // y
                new BigInteger("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", 16), // n
                BigInteger.One,
                null
                ));

			EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP256r1.ToString(), () => domainFuncGxy(
                new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16), // q
                new BigInteger("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16), // a
                new BigInteger("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16), // b
                new BigInteger("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), // x
                new BigInteger("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16), // y
                new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16), // n
                BigInteger.One,
                null
                ));

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP256t1.ToString(), () => domainFuncGxy(
                new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16), // q
                new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374", 16), // a
                new BigInteger("662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04", 16), // b
                new BigInteger("A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4", 16), // x
                new BigInteger("2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE", 16), // y
                new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16), // n
                BigInteger.One,
                null
                ));
			
			EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP320r1.ToString(), () => domainFuncGxy(
                new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27", 16), // q
                new BigInteger("3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4", 16), // a
                new BigInteger("520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6", 16), // b
                new BigInteger("43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611", 16), // x
                new BigInteger("14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1", 16), // y
                new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311", 16), // n
                BigInteger.One,
                null
                ));

            EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP384r1.ToString(), () => domainFuncGxy(
                new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16), // q
                new BigInteger("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16), // a
                new BigInteger("4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16), // b
                new BigInteger("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", 16), // x
                new BigInteger("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", 16), // y
                new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16), // n
                BigInteger.One,
                null
                ));
			
			EcParameters.Add(BrainpoolEllipticCurve.BrainpoolP512r1.ToString(), () => domainFuncGxy(
                new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16), // q
                new BigInteger("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16), // a
                new BigInteger("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16), // b
                new BigInteger("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16), // x
                new BigInteger("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16), // y
                new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16), // n
                BigInteger.One, // h
                null
                ));

            EcParameters.Add(Sec2EllipticCurve.Secp192k1.ToString(), () => domainFuncG(
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", 16), // q
                BigInteger.Zero, // a
                BigInteger.Three, // b
                "04DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", // g
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 16), // n
                BigInteger.One, // h
                null));

            EcParameters.Add(Sec2EllipticCurve.Secp192r1.ToString(), () => domainFuncG(
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16), // q
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16), // a
                new BigInteger("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16), // b
                "04188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF101207192B95FFC8DA78631011ED6B24CDD573F977A11E794811", // g
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16), // n
                BigInteger.One, // h
                "3045AE6FC8422F64ED579528D38120EAE12196D5"));

            EcParameters.Add(Sec2EllipticCurve.Secp224k1.ToString(), () => domainFuncG(
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D", 16), // q
                BigInteger.Zero, // a
                BigInteger.ValueOf(5), // b
                "04A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5", // g
                new BigInteger("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7", 16), // n
                BigInteger.One, // h
                null));

            EcParameters.Add(Sec2EllipticCurve.Secp224r1.ToString(), () => domainFuncG(
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16), // q
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16), // a
                new BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16), // b
                "04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", // g
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16), // n
                BigInteger.One, // h
                "BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5")); // s

            EcParameters.Add(Sec2EllipticCurve.Secp256k1.ToString(), () => domainFuncG(
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16), // q
                BigInteger.Zero, // a
                BigInteger.ValueOf(7), // b
                "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", // g
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16), // n
                BigInteger.One, // h
                null));

            EcParameters.Add(Sec2EllipticCurve.Secp256r1.ToString(), () => domainFuncG(
                new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16), // q
                new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16), // a
                new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16), // b
                "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", // g
                new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16), // n
                BigInteger.One, // h
                "C49D360886E704936A6678E1139D26B7819F7E90")); // s


            EcParameters.Add(Sec2EllipticCurve.Secp384r1.ToString(), () => domainFuncG(
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16), // q
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16), // a
                new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16), // b
                "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", // g
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16), // n
                BigInteger.One, // h
                "A335926AA319A27A1D00896A6773A4827ACDAC73")); // s

            EcParameters.Add(Sec2EllipticCurve.Secp521r1.ToString(), () => domainFuncG(
                new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16),
                new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16),
                new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16),
                "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", // g
                new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
                BigInteger.One,
                "D09E8800291CB85396CC6717393284AAA0DA64BA"));

            // Add curves over GF(2m)

            var domainFuncF2mK123 = new Func<int, int, int, int, BigInteger, BigInteger, string, BigInteger, BigInteger, string,
                ECDomainParameters>((m, k1, k2, k3, A, B, G, n, h, S) =>
                    {
                        var curve = new F2mCurve(m, k1, k2, k3, A, B, n, h);
                        return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), n, h, S.HexToBinary());
                    });
            var domainFuncF2m = new Func<int, int, BigInteger, BigInteger, string, BigInteger, BigInteger, string,
                ECDomainParameters>((m, k, A, B, G, n, h, S) =>
                    {
                        var curve = new F2mCurve(m, k, A, B, n, h);
                        return new ECDomainParameters(curve, curve.DecodePoint(G.HexToBinary()), n, h, S.HexToBinary());
                    });

            //EcParameters.Add(Sec2EllipticCurve.Sect163k1.ToString(), () => domainFuncF2mK123(
            //    163,
            //    3, 6, 7,
            //    BigInteger.One,
            //    BigInteger.Two,
            //    "0402FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE80289070FB05D38FF58321F2E800536D538CCDAA3D9",
            //    new BigInteger("04000000000000000000020108A2E0CC0D99F8A5EF", 16),
            //    BigInteger.One, 
            //    null));

            EcParameters.Add(Sec2EllipticCurve.Sect163r2.ToString(), () => domainFuncF2mK123(
                163,
                3, 6, 7,
                BigInteger.One,
                new BigInteger("020A601907B8C953CA1481EB10512F78744A3205FD", 16), 
                "0403F0EBA16286A2D57EA0991168D4994637E8343E3600D51FBC6C71A0094FA2CDD545B11C5C0C797324F1",
                new BigInteger("040000000000000000000292FE77E70C12A4234C33", 16),
                BigInteger.One, 
                "85E25BFE5C86226CDB12016F7553F9D0E693A268"));

            //EcParameters.Add(Sec2EllipticCurve.Sect233k1.ToString(), () => domainFuncF2m(
            //    233,
            //    74,
            //    BigInteger.Zero,
            //    BigInteger.One,
            //    "04017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD612601DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3",
            //    new BigInteger("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF", 16),
            //    BigInteger.ValueOf(4), 
            //    null));

            EcParameters.Add(Sec2EllipticCurve.Sect233r1.ToString(), () => domainFuncF2m(
                233,
                74,
                BigInteger.One,
                new BigInteger("0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD", 16), 
                "0400FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052",
                new BigInteger("01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7", 16),
                BigInteger.Two, 
                "74D59FF07F6B413D0EA14B344B20A2DB049B50C3"));

            //EcParameters.Add(Sec2EllipticCurve.Sect283k1.ToString(), () => domainFuncF2mK123(
            //    283,
            //    5, 7, 12,
            //    BigInteger.Zero,
            //    BigInteger.One,
            //    "040503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC245849283601CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259",
            //    new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61", 16),
            //    BigInteger.ValueOf(4), 
            //    null));

            EcParameters.Add(Sec2EllipticCurve.Sect283r1.ToString(), () => domainFuncF2mK123(
                283,
                5, 7, 12,
                BigInteger.One,
                new BigInteger("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5", 16),
                "0405F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B1205303676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4",
                new BigInteger("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307", 16),
                BigInteger.Two, 
                "77E2B07370EB0F832A6DD5B62DFC88CD06BB84BE"));

            //EcParameters.Add(Sec2EllipticCurve.Sect409k1.ToString(), () => domainFuncF2m(
            //    409,
            //    87,
            //    BigInteger.Zero,
            //    BigInteger.One,
            //    "040060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE902374601E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
            //    new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF", 16),
            //    BigInteger.ValueOf(4), 
            //    null));

            EcParameters.Add(Sec2EllipticCurve.Sect409r1.ToString(), () => domainFuncF2m(
                409,
                87,
                BigInteger.One,
                new BigInteger("0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F", 16),
                "04015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A70061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706",
                new BigInteger("010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173", 16),
                BigInteger.Two, 
                "4099B5A457F9D69F79213D094C4BCD4D4262210B"));

            //EcParameters.Add(Sec2EllipticCurve.Sect571k1.ToString(), () => domainFuncF2mK123(
            //    571,
            //    2, 5, 10,
            //    BigInteger.Zero,
            //    BigInteger.One,
            //    "04026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C89720349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3",
            //    new BigInteger("020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001", 16),
            //    BigInteger.ValueOf(4), 
            //    null));

            EcParameters.Add(Sec2EllipticCurve.Sect571r1.ToString(), () => domainFuncF2mK123(
                571,
                2, 5, 10,
                BigInteger.One,
                new BigInteger("02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A", 16),
                "040303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B",
                new BigInteger("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47", 16),
                BigInteger.Two, 
                "2AA058F73A0E33AB486B0F610410C53A7F132310"));


            // ######################################## PACKAGING ########################################

			PayloadLayoutModuleInstantiators.Add (PayloadLayoutScheme.Simple, (writing, multiplexedStream, manifest, config) => 
				new SimplePayloadMux (writing, multiplexedStream, manifest, config));
			PayloadLayoutModuleInstantiators.Add(PayloadLayoutScheme.Frameshift, (writing, multiplexedStream, manifest, config) => 
					new FrameshiftPayloadMux(writing, multiplexedStream, manifest, config));
#if(INCLUDE_FABRIC)
			PayloadLayoutModuleInstantiators.Add(PayloadLayoutScheme.Fabric, (writing, multiplexedStream, manifest, config) => 
				new FabricPayloadMux(writing, multiplexedStream, manifest, config));
#endif
            // ######################################## INIT END ########################################
        }

        // Block ciphers

        /// <summary>
        /// Instantiates and returns an implementation of the requested symmetric block cipher.
        /// </summary>
        /// <returns>An IBlockCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IBlockCipher CreateBlockCipher (SymmetricBlockCipher cipherEnum, int? blockSize = null) {
            if (blockSize == null) blockSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize;
            return EngineInstantiatorsBlock[cipherEnum](blockSize.Value);
        }

        public static IBlockCipher CreateBlockCipher (string cipherName, int? blockSize = null) {
            return CreateBlockCipher(cipherName.ToEnum<SymmetricBlockCipher>(), blockSize);
        }

        /// <summary>
        /// Implements a mode of operation on top of an existing block cipher. 
        /// Attention: CTS (CTS_CBC) mode invocations require further manipulation prior to use.
        /// </summary>
        /// <param name="cipher">The block cipher to implement this mode of operation on top of.</param>
        /// <param name="modeEnum">The mode of operation to implement.</param>
        /// <param name="size">Where applicable, the size parameter required for some modes of operation.</param>
        /// <returns>
        /// IBlockCipher object implementing the relevant mode of operation, 
        /// overlaying the supplied symmetric block cipher.
        /// </returns>
        public static IBlockCipher OverlayBlockCipherWithMode (IBlockCipher cipher, BlockCipherMode modeEnum, int? size = null) {
            if (cipher == null) {
                throw new ArgumentNullException();
            }
            var cipherMode = ModeInstantiatorsBlock[modeEnum](cipher, size ??
                    Athena.Cryptography.BlockCiphers[cipher.AlgorithmName.ToEnum<SymmetricBlockCipher>(true)]
                        .DefaultBlockSize);
            return cipherMode;
        }

        public static IBlockCipher OverlayBlockCipherWithMode (IBlockCipher cipher, string modeName, int? size = null) {
            return OverlayBlockCipherWithMode(cipher, modeName.ToEnum<BlockCipherMode>(), size);
        }

        /// <summary>
        /// Instantiates and returns an implementation of the requested padding mode. 
        /// Must be combined with a block cipher for operation.
        /// </summary>
        /// <returns>
        /// An IBlockCipherPadding cipher object implementing the relevant padding scheme.
        /// </returns>
        public static IBlockCipherPadding CreatePadding (BlockCipherPadding paddingEnum) {
            return PaddingInstantiators[paddingEnum]();
        }

        public static IBlockCipherPadding CreatePadding (string paddingName) {
            return CreatePadding(paddingName.ToEnum<BlockCipherPadding>());
        }

        // Block cipher parameters

        public static ICipherParameters CreateKeyParameter(SymmetricBlockCipher cipherEnum, byte[] key) {
            if (!Athena.Cryptography.BlockCiphers[cipherEnum].AllowableKeySizes.Contains(key.Length * 8))
                throw new InvalidDataException("Key size is unsupported/incompatible.");
            
            var cipherParams = new KeyParameter(key);
            return cipherParams;
        }

        public static ICipherParameters CreateBlockCipherParameters(ISymmetricCipherConfiguration config, byte[] key = null) {
            return CreateBlockCipherParameters(config.CipherName.ToEnum<SymmetricBlockCipher>(), key ?? config.Key, config.IV);
        }

        public static ICipherParameters CreateBlockCipherParameters(SymmetricBlockCipher cipherEnum, byte[] key, byte[] iv) {
            ICipherParameters cipherParams = null;

            if((iv == null || iv.Length == 0) && Athena.Cryptography.BlockCiphers[cipherEnum].DefaultIvSize != -1) 
                throw new NotSupportedException("IV is null or zero-zength.");

            if (cipherEnum.ToString().Equals(SymmetricBlockCipher.TripleDes.ToString())) {
                if(!Athena.Cryptography.BlockCiphers[cipherEnum].AllowableKeySizes.Contains(key.Length * 8)) 
                    throw new InvalidDataException("Key size is unsupported/incompatible.");
                cipherParams = new ParametersWithIV(new DesEdeParameters(key, 0, key.Length), iv, 0,
                    iv.Length);
            } else {
                cipherParams = new ParametersWithIV(CreateKeyParameter(cipherEnum, key), iv, 0, iv.Length);
            }

            return cipherParams;
        }

        // Stream ciphers

        /// <summary>
        /// Instantiates and returns a symmetric stream cipher of the algorithm type that the instance this method was called from describes.
        /// </summary>
        /// <returns>An IStreamCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IStreamCipher CreateStreamCipher (SymmetricStreamCipher cipherEnum) {
            return EngineInstantiatorsStream[cipherEnum]();
        }

        public static IStreamCipher CreateStreamCipher (string cipherName) {
            return EngineInstantiatorsStream[cipherName.ToEnum<SymmetricStreamCipher>()]();
        }

        // Stream cipher parameters

        public static ICipherParameters CreateKeyParameter(SymmetricStreamCipher cipherEnum, byte[] key) {
            if (!Athena.Cryptography.StreamCiphers[cipherEnum].AllowableKeySizes.Contains(key.Length * 8))
                throw new InvalidDataException("Key size is unsupported/incompatible.");

            var cipherParams = new KeyParameter(key);
            return cipherParams;
        }

        public static ICipherParameters CreateStreamCipherParameters(SymmetricStreamCipher cipherEnum, byte[] key, byte[] iv) {
#if(INCLUDE_RC4)
            if (cipher == SymmetricStreamCiphers.RC4) return CreateKeyParameter(key);
#endif
#if(INCLUDE_ISAAC)
            if (cipherEnum == SymmetricStreamCiphers.ISAAC) return CreateKeyParameter(cipherEnum, key);
#endif
            if (iv.IsNullOrZeroLength()) throw new InvalidDataException("IV is null or zero-length.");
            if (!Athena.Cryptography.StreamCiphers[cipherEnum].AllowableIvSizes.Contains(iv.Length * 8)) {
                throw new InvalidDataException("IV size is unsupported/incompatible.");
            }

            var cipherParams = new ParametersWithIV(CreateKeyParameter(cipherEnum, key), iv);
            return cipherParams;
        }

        // Authentication-related

		/// <summary>
		/// Instantiates and returns a hash/digest primitive.
		/// </summary>
		/// <param name="hashEnum">Hash/digest function to instantiate.</param>
		/// <returns>
		/// An digest object deriving from IDigest.
		/// </returns>
		public static IDigest CreateHashPrimitive (HashFunction hashEnum) {
			return DigestInstantiators[hashEnum]();
		}

		public static IDigest CreateHashPrimitive(string hashName) {
			return CreateHashPrimitive(hashName.ToEnum<HashFunction>());
		}

		/// <summary>
		/// Instantiates and initialises a Message Authentication Code (MAC) primitive.
		/// </summary>
		/// <param name="macEnum">MAC function to instantiate.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
		/// <param name="config">Configuration for the function, where applicable. For example,
		/// CMAC and HMAC use cipher and hash function names, repectively, encoded as UTF-8.</param>
		/// <returns>
		/// An MAC object deriving from IMac.
		/// </returns>
		public static IMac CreateMacPrimitive (MacFunction macEnum, byte[] key, byte[] salt = null, byte[] config = null) {

			IMac macObj;
			if (macEnum == MacFunction.Hmac) {
				if (config == null)
					throw new ArgumentException ("No hash function specified (encoded as UTF-8 bytes).", "config");
				return macObj = CreateHmacPrimitive(Encoding.UTF8.GetString(config).ToEnum<HashFunction>(), key, salt);
			} else if (macEnum == MacFunction.Cmac) {
				if (config == null)
					throw new ArgumentException ("No block cipher specified (encoded as UTF-8 bytes).", "config");
				macObj = CreateCmacPrimitive(Encoding.UTF8.GetString(config).ToEnum<SymmetricBlockCipher>(), key, salt);
			} else {
				macObj = MacInstantiators[macEnum]();
				if (Athena.Cryptography.MacFunctions [macEnum].SaltSupported && salt != null) {
					// Primitive has its own special salting procedure
					((IMacWithSalt)macObj).Init (key, salt);
					return macObj;
				}
				macObj.Init (new KeyParameter (key));
				if(!salt.IsNullOrZeroLength()) macObj.BlockUpdate(salt, 0, salt.Length);
			}

			return macObj;
		}

		public static IMac CreateMacPrimitive(string macName, byte[] key, byte[] salt = null, byte[] config = null) {
			return CreateMacPrimitive(macName.ToEnum<MacFunction>(), key, salt, config);
		}

		/// <summary>
		/// Creates a CMAC primitive using a symmetric block cipher primitive configured with default block size. 
		/// Default block sizes (and so, output sizes) can be found by querying Athena.
		/// </summary>
		/// <param name="cipherEnum">Cipher primitive to use as the basis for the CMAC construction.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
		/// <returns>Pre-initialised CMAC primitive.</returns>
		public static IMac CreateCmacPrimitive(SymmetricBlockCipher cipherEnum, byte[] key, byte[] salt = null) {
			var defaultBlockSize = Athena.Cryptography.BlockCiphers[cipherEnum].DefaultBlockSize;
			if(defaultBlockSize != 64 && defaultBlockSize != 128) {
				throw new NotSupportedException ("CMAC/OMAC1 only supports ciphers with 64 / 128 bit block sizes.");
			}
			var macObj = new CMac (CreateBlockCipher (cipherEnum, null));
			var keyParam = CreateKeyParameter (cipherEnum, key);
			macObj.Init (keyParam);
			if(salt != null && salt.Length > 0) macObj.BlockUpdate(salt, 0, salt.Length);

			return macObj;
		}

        /// <summary>
		/// Creates a HMAC primitive using a hash/digest primitive.
		/// </summary>
		/// <param name="hashEnum">Hash/digest primitive to use as the basis for the HMAC construction.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
		/// <returns>Pre-initialised HMAC primitive.</returns>
		public static IMac CreateHmacPrimitive(HashFunction hashEnum, byte[] key, byte[] salt = null) {
			var macObj = new HMac (DigestInstantiators [hashEnum]());
			var keyParam = new KeyParameter (key);
			macObj.Init (keyParam);
			if(!salt.IsNullOrZeroLength()) macObj.BlockUpdate(salt, 0, salt.Length);

			return macObj;
		}

        /// <summary>
        /// Derives a working key with the KDF module.
        /// </summary>
        /// <returns>The working key.</returns>
        /// <param name="kdfEnum">Key derivation function to use.</param>
        /// <param name="key">Pre-key to use as input material.</param>
        /// <param name="salt">Salt to use in derivation to increase entropy.</param>
        /// <param name="outputSize">Output key size in bits.</param>
        /// <param name="config">Serialised configuration of the KDF.</param>
        public static byte[] DeriveKeyWithKdf (KeyDerivationFunction kdfEnum, byte[] key, byte[] salt, int outputSize, byte[] config) {
			return KdfStatics[kdfEnum](key, salt, outputSize, config);
		}
		
		public static IKdfFunction CreateKdf(KeyDerivationFunction kdfEnum, int outputSize, byte[] config) {
			return KdfInstantiators[kdfEnum](outputSize, config);
		}

        public static IKdfFunction CreateKdf(string kdfName, int outputSize, byte[] config) {
            return CreateKdf(kdfName.ToEnum<KeyDerivationFunction>(), outputSize, config);
        }

        /// <summary>
        /// Instantiates and returns a CSPRNG implementing a generator function.
        /// </summary>
        /// <param name="csprngEnum">CSPRNG function to use.</param>
        /// <param name="config">Serialised configuration of the CSPRNG.</param>
        /// <returns>
        /// An CSPRNG object deriving from CSPRNG.
        /// </returns>
        public static Csprng CreateCsprng (CsPseudorandomNumberGenerator csprngEnum, byte[] config) {
			return PrngInstantiators[csprngEnum](config);
		}

        public static Csprng CreateCsprng (string csprngName, byte[] config) {
            return CreateCsprng(csprngName.ToEnum<CsPseudorandomNumberGenerator>(), config);
        }

        public static StreamCipherCsprngConfiguration CreateStreamCipherCsprngConfiguration
            (CsPseudorandomNumberGenerator cipherEnum)
        {
            return StreamCsprng.CreateRandomConfiguration(cipherEnum);
        }

        public static ECDomainParameters GetEcDomainParameters(BrainpoolEllipticCurve curveEnum) {
            if (curveEnum == BrainpoolEllipticCurve.None) {
                throw new ArgumentException();
            }
            return GetEcDomainParameters(curveEnum.ToString());
        }

        public static ECDomainParameters GetEcDomainParameters(Sec2EllipticCurve curveEnum) {
            if (curveEnum == Sec2EllipticCurve.None) {
                throw new ArgumentException();
            }
            return GetEcDomainParameters(curveEnum.ToString());
        }

        public static ECDomainParameters GetEcDomainParameters(string name) {
            if (!EcParameters.ContainsKey(name)) {
                throw new NotSupportedException("Named curve is unknown or unsupported.");
            }
            return EcParameters[name]();
        }


        // Packaging related

        /// <summary>
        /// Instantiates and returns a payload I/O module implementing the mode of operation that the
        /// instance this method was called from describes.
        /// </summary>
        /// <param name="schemeEnum">Payload layout scheme to choose the correspknding multiplexer.</param>
        /// <param name="writing">Whether the multiplexer will be multiplexing or demultiplexing.</param>
        /// <param name="multiplexedStream">Stream to multiplex/demultiplex to/from.</param>
        /// <param name="streams">Streams to multiplex/demultiplex to/from.</param>
        /// <param name="transforms">Transforms to apply to the payload items (e.g. encryption).</param>
        /// <param name="config">Configuration of the layout module/multiplexer.</param>
        /// <returns>
        /// An module object deriving from PayloadMultiplexer.
        /// </returns>
		public static PayloadMux CreatePayloadMultiplexer (PayloadLayoutScheme schemeEnum, bool writing, 
			Stream multiplexedStream, Manifest manifest, IPayloadConfiguration config)
		{
			return PayloadLayoutModuleInstantiators[schemeEnum](writing, multiplexedStream, manifest, config);
		}
    }
}
