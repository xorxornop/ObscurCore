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
        private readonly static IDictionary<SymmetricBlockCiphers, Func<int, IBlockCipher>> EngineInstantiatorsBlock =
            new Dictionary<SymmetricBlockCiphers, Func<int, IBlockCipher>>();
        private readonly static IDictionary<SymmetricStreamCiphers, Func<IStreamCipher>> EngineInstantiatorsStream =
            new Dictionary<SymmetricStreamCiphers, Func<IStreamCipher>>();

        private readonly static IDictionary<BlockCipherModes, Func<IBlockCipher, int, IBlockCipher>> ModeInstantiatorsBlock =
            new Dictionary<BlockCipherModes, Func<IBlockCipher, int, IBlockCipher>>();
        private readonly static IDictionary<AEADBlockCipherModes, Func<IBlockCipher, IAeadBlockCipher>> ModeInstantiatorsAead =
            new Dictionary<AEADBlockCipherModes, Func<IBlockCipher, IAeadBlockCipher>>();

        private readonly static IDictionary<BlockCipherPaddings, Func<IBlockCipherPadding>> PaddingInstantiators =
            new Dictionary<BlockCipherPaddings, Func<IBlockCipherPadding>>();

        private readonly static IDictionary<KeyDerivationFunctions, Func<int, byte[], IKDFModule>> KdfInstantiators =
			new Dictionary<KeyDerivationFunctions, Func<int, byte[], IKDFModule>>();
		
		private readonly static IDictionary<KeyDerivationFunctions, Func<byte[], byte[], int, byte[], byte[]>> KdfStatics =
			new Dictionary<KeyDerivationFunctions, Func<byte[], byte[], int, byte[], byte[]>>();

        private readonly static IDictionary<CSPRNumberGenerators, Func<byte[], CSPRNG>> PrngInstantiators =
			new Dictionary<CSPRNumberGenerators, Func<byte[], CSPRNG>>();

        private readonly static IDictionary<HashFunctions, Func<IDigest>> DigestInstantiators =
			new Dictionary<HashFunctions, Func<IDigest>>();

        private readonly static IDictionary<MACFunctions, Func<IMac>> MacInstantiators =
			new Dictionary<MACFunctions, Func<IMac>>();

        private readonly static IDictionary<string, Func<ECDomainParameters>> EcParameters =
			new Dictionary<string, Func<ECDomainParameters>>();

        // Packaging related

        private readonly static IDictionary<PayloadLayoutSchemes, Func<bool, Stream, IList<IStreamBinding>, IList<Func<Stream, DecoratingStream>>, 
			IPayloadConfiguration, StreamMux>> PayloadLayoutModuleInstantiators = new Dictionary<PayloadLayoutSchemes, 
		    Func<bool, Stream, IList<IStreamBinding>, IList<Func<Stream, DecoratingStream>>, IPayloadConfiguration, StreamMux>>();

        static Source() {
            // ######################################## ENGINES ########################################
            // Block engines
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.AES, blockSize => new AesFastEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.Blowfish, blockSize => new BlowfishEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.CAST5, blockSize => new Cast5Engine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.CAST6, blockSize => new Cast6Engine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.Camellia, blockSize => new CamelliaEngine());
#if INCLUDE_GOST28147
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.GOST28147, blockSize => new Gost28147Engine());
#endif
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.IDEA, blockSize => new IdeaEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.NOEKEON, blockSize => new NoekeonEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.RC6, blockSize => new RC6Engine());
#if INCLUDE_RIJNDAEL
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.Rijndael, blockSize => new RijndaelEngine(blockSize));
#endif
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.Serpent, blockSize => new SerpentEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.TripleDES, blockSize => new DesEdeEngine());
            EngineInstantiatorsBlock.Add(SymmetricBlockCiphers.Twofish, blockSize => new TwofishEngine());

            // Stream engines
            EngineInstantiatorsStream.Add(SymmetricStreamCiphers.HC128, () => new HC128Engine());
            EngineInstantiatorsStream.Add(SymmetricStreamCiphers.HC256, () => new HC256Engine());
#if INCLUDE_ISAAC
            EngineInstantiatorsStream.Add(SymmetricStreamCiphers.ISAAC, () => new IsaacEngine());
#endif
            EngineInstantiatorsStream.Add(SymmetricStreamCiphers.Rabbit, () => new RabbitEngine());
#if INCLUDE_RC4
            _engineInstantiatorsStream.Add(SymmetricStreamCiphers.RC4, () => new RC4Engine());
#endif
            EngineInstantiatorsStream.Add(SymmetricStreamCiphers.Salsa20, () => new Salsa20Engine());
            EngineInstantiatorsStream.Add(SymmetricStreamCiphers.SOSEMANUK, () => new SOSEMANUKEngine());
#if INCLUDE_VMPC
            EngineInstantiatorsBlock.Add(SymmetricStreamCiphers.VMPC, () => new VMPCEngine());
            EngineInstantiatorsBlock.Add(SymmetricStreamCiphers.VMPC_KSA3, () => new VMPCKSA3Engine());
#endif

            // ######################################## BLOCK MODES ########################################
            ModeInstantiatorsBlock.Add(BlockCipherModes.CBC, (cipher, size) => new CbcBlockCipher(cipher));
            ModeInstantiatorsBlock.Add(BlockCipherModes.CFB, (cipher, size) => new CfbBlockCipher(cipher, size));
            ModeInstantiatorsBlock.Add(BlockCipherModes.CTR, (cipher, size) => new SicBlockCipher(cipher));
            // CTS is not properly supported here...
            // Interim solution is just to return a CBC mode cipher, then it can be transformed into a CTS cipher afterwards. 
            // The return type is non-compatible :( .
            ModeInstantiatorsBlock.Add(BlockCipherModes.CTS_CBC, (cipher, size) => new CbcBlockCipher(cipher));
            ModeInstantiatorsBlock.Add(BlockCipherModes.OFB, (cipher, size) => new OfbBlockCipher(cipher, size));
            // AEAD modes
            ModeInstantiatorsAead.Add(AEADBlockCipherModes.EAX, cipher => new EaxBlockCipher(cipher));
            ModeInstantiatorsAead.Add(AEADBlockCipherModes.GCM, cipher => new GcmBlockCipher(cipher));
            //ModeInstantiatorsAead.Add(AEADBlockCipherModes.SIV, cipher => new SivBlockCipher(cipher));
			//ModeInstantiatorsAead.Add(AEADBlockCipherModes.OCB, cipher => new OcbBlockCipher(cipher));

            // ######################################## PADDING ########################################

            PaddingInstantiators.Add(BlockCipherPaddings.ISO10126D2, () => new ISO10126d2Padding());
            PaddingInstantiators.Add(BlockCipherPaddings.ISO7816D4, () => new ISO7816d4Padding());
            PaddingInstantiators.Add(BlockCipherPaddings.PKCS7, () => new ISO10126d2Padding());
            PaddingInstantiators.Add(BlockCipherPaddings.TBC, () => new ISO10126d2Padding());
            PaddingInstantiators.Add(BlockCipherPaddings.X923, () => new ISO10126d2Padding());

            // ######################################## KEY DERIVATION ########################################

            KdfInstantiators.Add(KeyDerivationFunctions.PBKDF2, (outputSize, config) => new PBKDF2Module(outputSize, config));
			KdfInstantiators.Add(KeyDerivationFunctions.Scrypt, (outputSize, config) => new ScryptModule(outputSize, config));
			
			KdfStatics.Add(KeyDerivationFunctions.PBKDF2, PBKDF2Module.DeriveKeyWithConfig);
			KdfStatics.Add(KeyDerivationFunctions.Scrypt, ScryptModule.DeriveKeyWithConfig);

            // ######################################## PRNG ########################################

            PrngInstantiators.Add(CSPRNumberGenerators.Salsa20, config => new Salsa20Generator(config));
			PrngInstantiators.Add(CSPRNumberGenerators.SOSEMANUK, config => new SOSEMANUKGenerator(config));

            // ######################################## HASHING ########################################

            DigestInstantiators.Add(HashFunctions.BLAKE2B256, () => new Blake2BDigest(256, true));
			DigestInstantiators.Add(HashFunctions.BLAKE2B384, () => new Blake2BDigest(384, true));
			DigestInstantiators.Add(HashFunctions.BLAKE2B512, () => new Blake2BDigest(512, true));

			DigestInstantiators.Add(HashFunctions.Keccak224, () => new KeccakManaged(224, true));
			DigestInstantiators.Add(HashFunctions.Keccak256, () => new KeccakManaged(256, true));
			DigestInstantiators.Add(HashFunctions.Keccak384, () => new KeccakManaged(384, true));
			DigestInstantiators.Add(HashFunctions.Keccak512, () => new KeccakManaged(512, true));

#if INCLUDE_SHA1
            DigestInstantiators.Add(HashFunctions.SHA1, () => new Sha1Digest());
#endif
            DigestInstantiators.Add(HashFunctions.SHA256, () => new Sha256Digest());
            DigestInstantiators.Add(HashFunctions.SHA512, () => new Sha512Digest());

            DigestInstantiators.Add(HashFunctions.RIPEMD160, () => new RipeMD160Digest());

            DigestInstantiators.Add(HashFunctions.Tiger, () => new TigerDigest());

            DigestInstantiators.Add(HashFunctions.Whirlpool, () => new WhirlpoolDigest());

            // ######################################## MAC ########################################

            MacInstantiators.Add(MACFunctions.BLAKE2B256, () => new Blake2BMac(256, true, false));
			MacInstantiators.Add(MACFunctions.BLAKE2B384, () => new Blake2BMac(384, true, false));
			MacInstantiators.Add(MACFunctions.BLAKE2B512, () => new Blake2BMac(512, true, false));

			MacInstantiators.Add(MACFunctions.Keccak224, () => new KeccakMac(224, true));
			MacInstantiators.Add(MACFunctions.Keccak256, () => new KeccakMac(256, true));
			MacInstantiators.Add(MACFunctions.Keccak384, () => new KeccakMac(384, true));
			MacInstantiators.Add(MACFunctions.Keccak512, () => new KeccakMac(512, true));

            // ######################################## EC ########################################

            var domainFunc = new Func<string, string, string, string, string, string, 
                ECDomainParameters>((p, A, B, x, y, q) =>
                {
                    var curve = new FpCurve(new BigInteger(p, 16), new BigInteger(A, 16), new BigInteger(B, 16));
			        return new ECDomainParameters(curve, curve.CreatePoint(new BigInteger(x, 16), 
				    	new BigInteger(y, 16), false), new BigInteger(q, 16));
                });

            EcParameters.Add(ECFpCurves.BrainpoolP160r1.ToString(), () => domainFunc(
				"E95E4A5F737059DC60DFC7AD95B3D8139515620F",
				"340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
				"1E589A8595423412134FAA2DBDEC95C8D8675E58",
				"BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",
				"1667CB477A1A8EC338F94741669C976316DA6321",
				"E95E4A5F737059DC60DF5991D45029409E60FC09"
				));
			
			EcParameters.Add(ECFpCurves.BrainpoolP192r1.ToString(), () => domainFunc(
				"C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
				"6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
				"469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
				"C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
				"14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
				"C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"
				));
			
			EcParameters.Add(ECFpCurves.BrainpoolP224r1.ToString(), () => domainFunc(
				"D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
				"68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
				"2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
				"0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
				"58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
				"D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"
				));
			
			EcParameters.Add(ECFpCurves.BrainpoolP256r1.ToString(), () => domainFunc(
				"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
				"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
				"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
				"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
				"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
				"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"
				));
			
			EcParameters.Add(ECFpCurves.BrainpoolP320r1.ToString(), () => domainFunc(
				"D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
				"3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
				"520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
				"43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
				"14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
				"D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"
				));
			
			EcParameters.Add(ECFpCurves.BrainpoolP384r1.ToString(), () => domainFunc(
				"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
				"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
				"4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
				"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
				"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
				"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"
				));
			
			EcParameters.Add(ECFpCurves.BrainpoolP512r1.ToString(), () => domainFunc(
				"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
				"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
				"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
				"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
				"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
				"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"
				));

            // ######################################## PACKAGING ########################################

            PayloadLayoutModuleInstantiators.Add(PayloadLayoutSchemes.Simple, (writing, multiplexedStream, streams, transforms, config) => 
			                         new SimpleMux(writing, multiplexedStream, streams, transforms, config));
			PayloadLayoutModuleInstantiators.Add(PayloadLayoutSchemes.Frameshift, (writing, multiplexedStream, streams, transforms, config) => 
			                         new FrameshiftMux(writing, multiplexedStream, streams, transforms, config));
#if(INCLUDE_FABRIC)
            PayloadLayoutModuleInstantiators.Add(PayloadLayoutSchemes.Fabric, (writing, multiplexedStream, streams, transforms, config) => 
			                                     new FabricMux(writing, multiplexedStream, streams, transforms, config));
#endif
            // ######################################## INIT END ########################################
        }

        // Block ciphers

        /// <summary>
        /// Instantiates and returns an implementation of the requested symmetric block cipher.
        /// </summary>
        /// <returns>An IBlockCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IBlockCipher CreateBlockCipher (SymmetricBlockCiphers cipherEnum, int? blockSize = null) {
            if (blockSize == null) blockSize = Athena.Cryptography.BlockCipherDirectory[cipherEnum].DefaultBlockSize;
            return EngineInstantiatorsBlock[cipherEnum](blockSize.Value);
        }

        public static IBlockCipher CreateBlockCipher (string cipherName, int? blockSize = null) {
            return CreateBlockCipher(cipherName.ToEnum<SymmetricBlockCiphers>(), blockSize);
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
        public static IBlockCipher OverlayBlockCipherWithMode (IBlockCipher cipher, BlockCipherModes modeEnum, int? size = null) {
            var cipherMode = ModeInstantiatorsBlock[modeEnum](cipher, size ??
                (cipher != null ? Athena.Cryptography.BlockCipherDirectory[cipher.AlgorithmName.ToEnum<SymmetricBlockCiphers>(true)]
                    .DefaultBlockSize : cipher.GetBlockSize()));
            return cipherMode;
        }

        public static IBlockCipher OverlayBlockCipherWithMode (IBlockCipher cipher, string modeName, int? size = null) {
            return OverlayBlockCipherWithMode(cipher, modeName.ToEnum<BlockCipherModes>(), size);
        }

        /// <summary>
        /// Instantiates and returns an implementation of the requested padding mode. 
        /// Must be combined with a block cipher for operation.
        /// </summary>
        /// <returns>
        /// An IBlockCipherPadding cipher object implementing the relevant padding scheme.
        /// </returns>
        public static IBlockCipherPadding CreatePadding (BlockCipherPaddings paddingEnum) {
            return PaddingInstantiators[paddingEnum]();
        }

        public static IBlockCipherPadding CreatePadding (string paddingName) {
            return CreatePadding(paddingName.ToEnum<BlockCipherPaddings>());
        }

        /// <summary>
        /// Implements an Authenticated Encryption/Decryption (AEAD) mode of operation on top of an existing block cipher. 
        /// </summary>
        /// <param name="cipher">The block cipher to implement this mode of operation on top of.</param>
        /// <param name="modeEnum">The mode of operation to implement.</param>
        /// <returns>
        /// IAeadBlockCipher object implementing the relevant mode of operation, 
        /// overlaying the supplied symmetric block cipher.
        /// </returns>
        public static IAeadBlockCipher OverlayBlockCipherWithAEADMode (IBlockCipher cipher, AEADBlockCipherModes modeEnum) {
            return ModeInstantiatorsAead[modeEnum](cipher);
        }

        public static IAeadBlockCipher OverlayBlockCipherWithAEADMode (IBlockCipher cipher, string modeName) {
            return ModeInstantiatorsAead[modeName.ToEnum<AEADBlockCipherModes>()](cipher);
        }

        // Block cipher parameters

        public static ICipherParameters CreateKeyParameter(SymmetricBlockCiphers cipherEnum, byte[] key) {
            if (!Athena.Cryptography.BlockCipherDirectory[cipherEnum].AllowableKeySizes.Contains(key.Length * 8))
                throw new InvalidDataException("Key size is unsupported/incompatible.");
            
            var cipherParams = new KeyParameter(key);
            return cipherParams;
        }

        public static ICipherParameters CreateBlockCipherParameters(ISymmetricCipherConfiguration config) {
            return CreateBlockCipherParameters(config.CipherName.ToEnum<SymmetricBlockCiphers>(), config.Key, config.IV);
        }

        public static ICipherParameters CreateBlockCipherParameters(SymmetricBlockCiphers cipherEnum, byte[] key, byte[] iv) {
            ICipherParameters cipherParams = null;

            if((iv == null || iv.Length == 0) && Athena.Cryptography.BlockCipherDirectory[cipherEnum].DefaultIVSize != -1) 
                throw new NotSupportedException("IV is null or zero-zength.");

            if (cipherEnum.ToString().Equals(SymmetricBlockCiphers.TripleDES.ToString())) {
                if(!Athena.Cryptography.BlockCipherDirectory[cipherEnum].AllowableKeySizes.Contains(key.Length * 8)) 
                    throw new InvalidDataException("Key size is unsupported/incompatible.");
                cipherParams = new ParametersWithIV(new DesEdeParameters(key, 0, key.Length), iv, 0,
                    iv.Length);
            } else {
                cipherParams = new ParametersWithIV(CreateKeyParameter(cipherEnum, key), iv, 0, iv.Length);
            }

            return cipherParams;
        }

        public static ICipherParameters CreateAEADBlockCipherParameters(SymmetricBlockCiphers cipherEnum, byte[] key, byte[] iv, 
            int macSizeBits, byte[] ad)
		{
            ICipherParameters cipherParams = null;

            if(!Athena.Cryptography.BlockCipherDirectory[cipherEnum].AllowableBlockSizes.Contains(macSizeBits)) 
                throw new InvalidDataException("MAC size is unsupported/incompatible.");

            if (cipherEnum == SymmetricBlockCiphers.TripleDES) {
                // Treat 3DES differently to other ciphers for key parameter object creation
                cipherParams = new AeadParameters(new DesEdeParameters(key, 0, key.Length), macSizeBits, iv,
                    ad ?? new byte[0]);
            } else {
                cipherParams = new AeadParameters(new KeyParameter(key, 0, key.Length), macSizeBits, iv,
                    ad ?? new byte[0]);
            }

            return cipherParams;
        }

        // Stream ciphers

        /// <summary>
        /// Instantiates and returns a symmetric stream cipher of the algorithm type that the instance this method was called from describes.
        /// </summary>
        /// <returns>An IStreamCipher cipher object implementing the relevant cipher algorithm.</returns>
        public static IStreamCipher CreateStreamCipher (SymmetricStreamCiphers cipherEnum) {
            return EngineInstantiatorsStream[cipherEnum]();
        }

        public static IStreamCipher CreateStreamCipher (string cipherName) {
            return EngineInstantiatorsStream[cipherName.ToEnum<SymmetricStreamCiphers>()]();
        }

        // Stream cipher parameters

        public static ICipherParameters CreateKeyParameter(SymmetricStreamCiphers cipherEnum, byte[] key) {
            if (!Athena.Cryptography.StreamCipherDirectory[cipherEnum].AllowableKeySizes.Contains(key.Length * 8))
                throw new InvalidDataException("Key size is unsupported/incompatible.");

            var cipherParams = new KeyParameter(key);
            return cipherParams;
        }

        public static ICipherParameters CreateStreamCipherParameters(SymmetricStreamCiphers cipherEnum, byte[] key, byte[] iv) {
#if(INCLUDE_RC4)
            if (cipher == SymmetricStreamCiphers.RC4) return CreateKeyParameter(key);
#endif
#if(INCLUDE_ISAAC)
            if (cipherEnum == SymmetricStreamCiphers.ISAAC) return CreateKeyParameter(cipherEnum, key);
#endif
            if (iv == null || iv.Length == 0) throw new InvalidDataException("IV is null or zero-length.");
            if (!Athena.Cryptography.StreamCipherDirectory[cipherEnum].AllowableIVSizes.Contains(iv.Length * 8)) {
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
		public static IDigest CreateHashPrimitive (HashFunctions hashEnum) {
			return DigestInstantiators[hashEnum]();
		}

		public static IDigest CreateHashPrimitive(string hashName) {
			return CreateHashPrimitive(hashName.ToEnum<HashFunctions>());
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
		public static IMac CreateMACPrimitive (MACFunctions macEnum, byte[] key, byte[] salt = null, byte[] config = null) {

			IMac macObj;
			if (macEnum == MACFunctions.HMAC) {
				if (config == null)
					throw new ArgumentException ("No hash function specified (encoded as UTF-8 bytes).", "config");
				return macObj = CreateHMACPrimitive(Encoding.UTF8.GetString(config).ToEnum<HashFunctions>(), key, salt);
			} else if (macEnum == MACFunctions.CMAC) {
				if (config == null)
					throw new ArgumentException ("No block cipher specified (encoded as UTF-8 bytes).", "config");
				macObj = CreateCMACPrimitive(Encoding.UTF8.GetString(config).ToEnum<SymmetricBlockCiphers>(), key, salt);
			} else {
				macObj = MacInstantiators[macEnum]();
				if (Athena.Cryptography.MACFunctionDirectory [macEnum].SaltSupported && salt != null) {
					// Primitive has its own special salting procedure
					((IMacWithSalt)macObj).Init (key, salt);
					return macObj;
				}
				macObj.Init (new KeyParameter (key));
				if(salt != null && salt.Length > 0) macObj.BlockUpdate(salt, 0, salt.Length);
			}

			return macObj;
		}

		public static IMac CreateMACPrimitive(string macName, byte[] key, byte[] salt = null, byte[] config = null) {
			return CreateMACPrimitive(macName.ToEnum<MACFunctions>(), key, salt, config);
		}

		/// <summary>
		/// Creates a CMAC primitive using a symmetric block cipher primitive configured with default block size. 
		/// Default block sizes (and so, output sizes) can be found by querying Athena.
		/// </summary>
		/// <param name="cipherEnum">Cipher primitive to use as the basis for the CMAC construction.</param>
		/// <param name="key">Cryptographic key to use in the MAC operation.</param>
		/// <param name="salt">Cryptographic salt to use in the MAC operation, if any.</param>
		/// <returns>Pre-initialised CMAC primitive.</returns>
		public static IMac CreateCMACPrimitive(SymmetricBlockCiphers cipherEnum, byte[] key, byte[] salt = null) {
			var defaultBlockSize = Athena.Cryptography.BlockCipherDirectory[cipherEnum].DefaultBlockSize;
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
		public static IMac CreateHMACPrimitive(HashFunctions hashEnum, byte[] key, byte[] salt = null) {
			var macObj = new HMac (DigestInstantiators [hashEnum]());
			var keyParam = new KeyParameter (key);
			macObj.Init (keyParam);
			if(salt != null && salt.Length > 0) macObj.BlockUpdate(salt, 0, salt.Length);

			return macObj;
		}

        /// <summary>
		/// Derives a working key with the KDF module.
		/// </summary>
		/// <returns>The working key.</returns>
		/// <param name="key">Pre-key to use as input material.</param>
		/// <param name="salt">Salt to use in derivation to increase entropy.</param>
		/// <param name="outputSize">Output key size in bits.</param>
		/// <param name="config">Configuration of the KDF in byte-array encoded form.</param>
		public static byte[] DeriveKeyWithKDF (KeyDerivationFunctions kdfEnum, byte[] key, byte[] salt, int outputSize, byte[] config) {
			return KdfStatics[kdfEnum](key, salt, outputSize, config);
		}
		
		public static IKDFModule CreateKDF(KeyDerivationFunctions kdfEnum, int outputSize, byte[] config) {
			return KdfInstantiators[kdfEnum](outputSize, config);
		}

        public static IKDFModule CreateKDF(string kdfName, int outputSize, byte[] config) {
            return CreateKDF(kdfName.ToEnum<KeyDerivationFunctions>(), outputSize, config);
        }





        

        

        

        

        


        

        /// <summary>
		/// Instantiates and returns a PRNG implementing the mode of generation that the
		/// instance this method was called from describes.
		/// </summary>
		/// <param name="config">Configuration of the PRNG in byte-array encoded form.</param>
		/// <returns>
		/// An PRNG object deriving from Random.
		/// </returns>
        public static CSPRNG CreateCSPRNG (CSPRNumberGenerators csprngEnum, byte[] config) {
			return PrngInstantiators[csprngEnum](config);
		}

        public static CSPRNG CreateCSPRNG (string csprngName, byte[] config) {
            return CreateCSPRNG(csprngName.ToEnum<CSPRNumberGenerators>(), config);
        }

        public static StreamCipherCSPRNGConfiguration CreateStreamCipherCSPRNGConfiguration
            (CSPRNumberGenerators cipherEnum)
        {
            return StreamCSPRNG.CreateRandomConfiguration(cipherEnum);
        }

        public static ECDomainParameters GetECDomainParameters(ECFpCurves curveEnum) {
            return GetECDomainParameters(curveEnum.ToString());
        }

        public static ECDomainParameters GetECDomainParameters(string name) {
            // Add extra checks if more curves are added
            ECFpCurves curve;
            if (!Enum.TryParse<ECFpCurves>(name, out curve)) {
                throw new NotSupportedException("Curve is unknown or otherwise unsupported.");
            }
            return EcParameters[name]();
        }

        

        // Packaging related

        /// <summary>
		/// Instantiates and returns a payload I/O module implementing the mode of operation that the
		/// instance this method was called from describes.
		/// </summary>
		/// <param name="config">Configuration of the module.</param>
		/// <returns>
		/// An module object deriving from IPayloadModule.
		/// </returns>
		public static StreamMux CreatePayloadMultiplexer (PayloadLayoutSchemes scheme, bool writing, Stream multiplexedStream, IList<IStreamBinding> streams, 
		                                            IList<Func<Stream, DecoratingStream>> transforms, IPayloadConfiguration config)
		{
			return PayloadLayoutModuleInstantiators[scheme](writing, multiplexedStream, streams, transforms, config);
		}
    }
}
