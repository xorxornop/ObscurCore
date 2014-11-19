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
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Support;

namespace ObscurCore.Tests.Cryptography.Digests
{
    public class Sha512 : DigestTestBase
    {
        public Sha512()
            : base(HashFunction.Sha512)
        {
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"));
        }
    }

    public class Sha256 : DigestTestBase
    {
        public Sha256()
            : base(HashFunction.Sha256)
        {
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
        }
    }

#if INCLUDE_SHA1
    public class Sha1 : DigestTestBase
    {
        public Sha1()
            : base(HashFunction.Sha1)
        {
            
        }
    }
#endif

    public class Blake2B256 : DigestTestBase
    {
        public Blake2B256()
            : base(HashFunction.Blake2B256)
        {
            
        }
    }

    public class Blake2B384 : DigestTestBase
    {
        public Blake2B384()
            : base(HashFunction.Blake2B384)
        {
            
        }
    }

    public class Blake2B512 : DigestTestBase
    {
        public Blake2B512()
            : base(HashFunction.Blake2B512)
        {
            
        }
    }

    public class Keccak224 : DigestTestBase
    {
        public Keccak224()
            : base(HashFunction.Keccak224)
        {
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "".HexToBinary(), "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67".HexToBinary(), "310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e".HexToBinary(), "c59d4eaeac728671c635ff645014e2afa935bebffdb5fbd207ffdeab".HexToBinary()));
        }
    }

    public class Keccak256 : DigestTestBase
    {
        public Keccak256()
            : base(HashFunction.Keccak256)
        {
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "".HexToBinary(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67".HexToBinary(), "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e".HexToBinary(), "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d".HexToBinary()));
        }
    }

    public class Keccak384 : DigestTestBase
    {
        public Keccak384()
            : base(HashFunction.Keccak384)
        {
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "".HexToBinary(), "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67".HexToBinary(), "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e".HexToBinary(), "9ad8e17325408eddb6edee6147f13856ad819bb7532668b605a24a2d958f88bd5c169e56dc4b2f89ffd325f6006d820b".HexToBinary()));
        }
    }

    public class Keccak512 : DigestTestBase
    {
        public Keccak512()
            : base(HashFunction.Keccak512)
        {
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "".HexToBinary(), "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67".HexToBinary(), "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609".HexToBinary()));
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e".HexToBinary(), "ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760".HexToBinary()));
        }
    }

    public class RipeMD160 : DigestTestBase
    {
        public RipeMD160()
            : base(HashFunction.Ripemd160)
        {
            
        }
    }

    public class Tiger : DigestTestBase
    {
        public Tiger()
            : base(HashFunction.Tiger)
        {
            
        }
    }

    public class Whirlpool : DigestTestBase
    {
        public Whirlpool()
            : base(HashFunction.Whirlpool)
        {
            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "", "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "a", "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "abc",  "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "message digest", "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "abcdefghijklmnopqrstuvwxyz", "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB6014294D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B"));

            DiscreteVectorTests.Add(new DiscreteVectorDigestTestCase("", base.Hash, "abcdbcdecdefdefgefghfghighijhijk", "2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C6916BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD"));
        }
    }
}
